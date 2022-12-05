use anyhow::{anyhow, Result};
use async_trait::async_trait;
use oxidant::{
    AgentServer, Identity, KeyConstraint, SSHAgent
};
use sshcerts::{
    ssh::SSHCertificateSigner,
    Certificate, PrivateKey,
};
use std::{
    collections::HashSet,
    ffi::CStr,
    io,
    ptr::copy_nonoverlapping,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions},
    runtime::Handle,
    sync::Mutex,
    time,
};
use windows::{
    core::{PCWSTR},
    w,
    Win32::Foundation::{HWND, LPARAM},
    Win32::{
        Foundation::{CloseHandle, LRESULT, WPARAM},
        Security::SID,
        System::{
            DataExchange::COPYDATASTRUCT,
            LibraryLoader::GetModuleHandleW,
            Memory::{
                MapViewOfFile, OpenFileMappingW, UnmapViewOfFile, FILE_MAP_WRITE,
            },
        },
        UI::WindowsAndMessaging::*
        // UI::WindowsAndMessaging::{
        //     CreateWindowExW, DefWindowProcW, DispatchMessageW, FindWindowW, GetClassLongPtrW, GetMessageW, LoadCursorW, PostQuitMessage, RegisterClassW,
        //     TranslateMessage, CS_HREDRAW, CW_USEDEFAULT, GET_CLASS_LONG_INDEX, HWND_MESSAGE,
        //     IDC_ARROW, MSG, WINDOW_EX_STYLE, WM_COPYDATA, WNDCLASSW, WS_CAPTION,
        // },
    },
    Win32::{UI::WindowsAndMessaging::{SetClassLongPtrW, GetWindowTextW, GetWindowTextLengthW}},
};

// TODO
// implement remaining missing features of the RFC
// unix sockets
// Validate proper origin for windows pipes and pageant
// gui
// yubikeys! piv only or also fido2/webauthn?
// tpm maybe?
// this maybe? https://www.openssh.com/agent-restrict.html
// macos secure enclave support? e.g. https://github.com/sekey/sekey but no way I can test...

const MAX_MESSAGE_SIZE: usize = (1<<17) - 1; // 128 KiB; as a sanity check we cap all incoming messages to this size
const PIPE_NAME: &str = r"\\.\pipe\openssh-ssh-agent";
const MAX_UNLOCK_ATTEMPTS: u8 = 10;

#[tokio::main]
async fn main() -> Result<()> {
    let mut agent = Agent {
        extensions: vec![String::from("query"), String::from("version")],
        identities: HashSet::new(),
        privatekey_lock: None,
        remaining_unlock_attempts: MAX_UNLOCK_ATTEMPTS,
    };

    agent.extensions.push("session-bind@openssh.com".into());

    let agt = Arc::new(Mutex::new(AgentServer::new(agent)));
    let agent = agt.clone();
    let handle = tokio::spawn(async move { pipestuff(agent).await });

    create_pageant_wrapper(agt.clone())?;

    handle.await??;
    Ok(())
}

fn assert_pageant(exists: bool) -> Result<()> {
    let window = unsafe { FindWindowW(w!("Pageant"), w!("Pageant")) };
    if window.0 != 0 {
        if exists {
            Ok(())
        } else {
            println!("window named {}", get_window_name(window));
            Err(anyhow!("Pageant is already running"))
        }
    } else if exists {
        Err(anyhow!("Failed to start pageant wrapper."))
    } else {
        Ok(())
    }
}

fn create_pageant_wrapper(agent: Arc<Mutex<AgentServer<Agent>>>) -> Result<()> {
    assert_pageant(false)?; // Assert that pageant isn't already running
        let instance = unsafe {GetModuleHandleW(None)}?;
        debug_assert!(instance.0 != 0);

        // Name of the window and registered class

        let wc = WNDCLASSW {
            hCursor: unsafe {LoadCursorW(None, IDC_ARROW)}?,
            hInstance: instance,
            lpszClassName: w!("Pageant"),
            cbClsExtra: std::mem::size_of::<*const Arc<Mutex<AgentServer<Agent>>>>() as _,
            lpfnWndProc: Some(wndproc),
            ..Default::default()
        };

        let atom = unsafe {RegisterClassW(&wc)};
        debug_assert!(atom != 0);

        let window = unsafe {CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("Pageant"),
            w!("Pageant"),
            WS_CAPTION,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            Some(HWND_MESSAGE),
            None,
            instance,
            None,
        )};

        unsafe {SetClassLongPtrW(window, GET_CLASS_LONG_INDEX(0), &agent as *const _ as isize)};

        if window.0 == 0 {
            println!("The window didn't open...");
        }
        let mut message = MSG::default();
        let window_name = get_window_name(window);

        println!("Window started, name is {window_name}");
        assert_pageant(true)?; // Assert that our pageant wrapper is now running

        loop {
            let res = unsafe {GetMessageW(&mut message, None, 0, 0)};
            if !res.as_bool() {
                // If the function retrieves the WM_QUIT message, the return value is zero, so break the loop and we're done
                break;
            }

            unsafe {TranslateMessage(&message);
            DispatchMessageW(&message);}
        }

        Ok(())
}

fn get_window_name(window: HWND) -> String {
    let length = unsafe {GetWindowTextLengthW(window)} as usize;
    let mut wt = vec![0u16; length+1]; // Account for null terminator
    unsafe {GetWindowTextW(window, &mut wt)};
    String::from_utf16_lossy(&wt)
}

macro_rules! strtoCWide {
    ($x:expr) => {
        {
            let mut w_string: Vec<u16> = $x.encode_utf16().collect();
            w_string.push(0);
            w_string.as_ptr()
        }
    };
}

extern "system" fn wndproc(window: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    // Per MS documentation: If the receiving application processes this message, it should return TRUE, i.e. LRESULT(1); otherwise, it should return FALSE, i.e. LRESULT(0).
    unsafe {
        match message {
            WM_COPYDATA => {
                println!("I've been called to action!");
                let pcds = lparam.0 as *const u8;
                let copydata: &COPYDATASTRUCT =
                    &*(pcds as *const windows::Win32::System::DataExchange::COPYDATASTRUCT);
                let map_name = CStr::from_ptr(copydata.lpData as _).to_str().unwrap();
                println!("Received Pageant file map: {}", map_name);

                let file_map_handle = if let Ok(hmap) = OpenFileMappingW(
                    FILE_MAP_WRITE.0,
                    false,
                    PCWSTR(strtoCWide!(map_name)),
                ) {
                    hmap
                } else {
                    return LRESULT(0);
                };

                let map_ptr = MapViewOfFile(file_map_handle, FILE_MAP_WRITE, 0, 0, 0);
                let message_size = if copydata.cbData >= 4 {
                    let agent_message_size_bytes = std::slice::from_raw_parts(map_ptr as *mut u8, 4);
                    u32::from_be_bytes(agent_message_size_bytes.try_into().unwrap()) + 4
                } else {
                    eprintln!("Pageant message received was too short");
                    return LRESULT(0)
                };
                let agent_message = std::slice::from_raw_parts_mut(map_ptr as *mut u8, MAX_MESSAGE_SIZE);

                let agent = &*(GetClassLongPtrW(window, GET_CLASS_LONG_INDEX(0))
                    as *mut Arc<Mutex<AgentServer<Agent>>>);
                let agt = agent.clone();

                println!("agent message: \n {:02x?}", &agent_message[0..message_size as _]);

                let handle = Handle::current();
                let task = handle.spawn(async move {
                    let mut agent = agt.lock().await;
                    let agent_resp = agent.message(&agent_message[0..message_size as _]).await.into_owned();
                    println!("agent reply: \n {:02x?}", &agent_resp);
                    copy_nonoverlapping(
                        agent_resp.as_ptr(),
                        agent_message.as_mut_ptr(),
                        agent_resp.len(),
                    );
                });
                // Make sure the async tasks are all done before we drop the file mappers, lest we cause undefined behavior.
                while !task.is_finished() {
                    std::thread::sleep(Duration::from_millis(10))
                }

                UnmapViewOfFile(map_ptr);
                CloseHandle(file_map_handle);

                LRESULT(1)
            },
            WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            },
            _ => DefWindowProcW(window, message, wparam, lparam),
        }
    }
}

async fn pipestuff(agent: Arc<Mutex<AgentServer<Agent>>>) -> Result<()> {
    loop {
        let server = ServerOptions::new().create(PIPE_NAME)?;
        // Wait for the client to connect
        let agt = agent.clone();
        server.connect().await?;
        tokio::spawn(async move {
            println!("Session started");
            if let Err(e) = pipeserver(server, agt).await {
                eprintln!("Session ended with error: {e}");
            } else {
                println!("Session ended");
            }
        });
    }
}

async fn pipeserver(server: NamedPipeServer, agent: Arc<Mutex<AgentServer<Agent>>>) -> Result<()> {
    loop {
        let length = server.read_u32().await?;
        if length == 0 {
            // Zero length message means it has nothing to send, ergo it's done.
            server.disconnect()?;
            break;
        }
        println!("incoming message length {}", length + 4);
        let mut data = server.read_bytes(length as _).await?;

        let mut send_data = Vec::with_capacity((length + 4) as _);
        send_data.append(&mut length.to_be_bytes().to_vec());
        send_data.append(&mut data);
        println!("{:02x?}", send_data);

        let mut agt = agent.lock().await;
        let msg = agt.message(send_data.as_slice()).await;
        println!("outgoing message length {}", msg.len());
        println!("{:02x?}", msg);
        server.write_bytes(&msg).await?;
    }
    Ok(())
}

const ERR_NOT_IMPLEMENTED: &str = "Error: Not Implemented";

struct Agent {
    extensions: Vec<String>,
    identities: HashSet<SSHIdentity>,
    privatekey_lock: Option<Vec<u8>>,
    remaining_unlock_attempts: u8,
}

#[async_trait]
impl SSHAgent for Agent {
    async fn request_identities(&self) -> Result<Vec<&Identity>> {
        let identities = self
            .identities
            .iter()
            .map(|i| &i.identity)
            .collect::<Vec<_>>();
        Ok(identities)
    }

    async fn sign_message(
        &self,
        identity: Identity,
        data: &[u8],
        flags: u32, //TODO: add sign flags to sshcerts library as some SSH servers want it
    ) -> Result<Vec<u8>> {
        if flags != 0 {
            println!("it's asking for flags {flags}")
        }
        if self.privatekey_lock.is_some() {
            return Err(anyhow!(
                "Agent is currently locked, all private key operations are blocked."
            ));
        }

        let tempid = SSHIdentity::from_identity(identity);
        if let Some(id) = self.identities.get(&tempid) {
            if let Some(private_key) = id.private_key.as_ref() {
                return private_key
                    .sign(data)
                    .ok_or_else(|| anyhow!("I'm not going to sign that."));
            }
            return Err(anyhow!("Requested identity has no private key"));
        }
        Err(anyhow!("No matching key found!"))
    }

    async fn add_id(
        &mut self,
        private_key: PrivateKey,
        constraints: Option<Vec<KeyConstraint>>,
    ) -> Result<()> {
        let comment = Some(private_key.comment.clone());
        let mut pubkey = private_key.pubkey.clone();
        pubkey.comment = comment;
        let identity = Identity::PublicKey(pubkey);
        let sshid = SSHIdentity {
            identity,
            private_key: Some(private_key),
            constraints,
        };
        self.identities.insert(sshid);
        Ok(())
    }

    async fn remove(&mut self, identity: Identity) -> Result<()> {
        let sshid = SSHIdentity::from_identity(identity);
        let removed = self.identities.remove(&sshid);
        if removed {
            Ok(())
        } else {
            Err(anyhow!("Identity wasn't removed because it doesn't exist."))
        }
    }

    async fn remove_all(&mut self) -> Result<()> {
        self.identities.clear();
        Ok(())
    }

    async fn add_sc_key(
        &mut self,
        id: &[u8],
        pin: Option<&[u8]>,
        constraints: Option<Vec<KeyConstraint>>,
    ) -> Result<()> {
        println!(
            "it wants me to add card id {} with pin {} and constraints {:?}",
            String::from_utf8_lossy(id),
            String::from_utf8_lossy(pin.unwrap_or_default()),
            constraints
        );
        println!("but I don't wanna");
        Err(anyhow!(ERR_NOT_IMPLEMENTED))
    }

    async fn remove_sc_key(&mut self, id: &[u8]) -> Result<()> {
        Err(anyhow!(ERR_NOT_IMPLEMENTED))
    }

    fn lock(&mut self, passphrase: &[u8]) -> Result<()> {
        if self.privatekey_lock.is_some() {
            return Err(anyhow!(
                "Ignoring lock request as the agent is already locked."
            ));
        }
        self.privatekey_lock = Some(passphrase.to_vec());
        self.remaining_unlock_attempts = MAX_UNLOCK_ATTEMPTS;
        Ok(())
    }

    async fn unlock(&mut self, passphrase: &[u8]) -> Result<()> {
        if let Some(phrase) = self.privatekey_lock.as_ref() {
            if phrase == passphrase {
                self.privatekey_lock = None;
                Ok(())
            } else {
                if self.remaining_unlock_attempts == 0 {
                    // Remove all identities from the agent if too many failed unlock attempts were tried
                    self.remove_all().await?;
                    // Then just unlock it again so we have a clean slate
                    self.privatekey_lock = None;
                    // Congratulations, it's unlocked :)
                    return Ok(());
                }
                self.remaining_unlock_attempts -= 1;
                Err(anyhow!(
                    "Unlock failed: Passphrase doesn't match. {} attempts remaining.",
                    self.remaining_unlock_attempts
                ))
            }
        } else {
            Err(anyhow!("Agent is already unlocked"))
        }
    }
    async fn extension(&mut self, name: &str, data: &[u8]) -> Result<Option<Vec<u8>>> {
        println!("{name}");
        Err(anyhow!(ERR_NOT_IMPLEMENTED))
    }
    fn extension_query(&self) -> Option<&Vec<String>> {
        Some(&self.extensions)
    }
    fn version(&self) -> &str {
        stringify!(env!("CARGO_PKG_NAME") env!("CARGO_PKG_VERSION"))
    }
}

#[async_trait]
trait OpenSSHPipe {
    async fn read_byte(&self) -> Result<u8>;
    async fn read_u32(&self) -> Result<u32>;
    async fn read_bytes(&self, size: usize) -> Result<Vec<u8>>;
    async fn write_bytes(&self, data: &[u8]) -> Result<usize>;
}

macro_rules! pipe_extensions {
    ( $x:ident ) => {
        #[async_trait]
        impl OpenSSHPipe for $x {
            async fn read_byte(&self) -> Result<u8> {
                Ok(self.read_bytes(1).await?[0])
            }

            async fn read_u32(&self) -> Result<u32> {
                let bytes: [u8; 4] = self.read_bytes(4).await?.try_into().unwrap_or([0u8; 4]);
                Ok(u32::from_be_bytes(bytes))
            }

            async fn read_bytes(&self, size: usize) -> Result<Vec<u8>> {
                let mut fail = String::new();
                for _ in 0..3 {
                    let mut data = Vec::with_capacity(size);
                    // Wait for the socket to be readable
                    self.readable().await?;

                    // Try to read data, this may still fail with `WouldBlock`
                    // if the readiness event is a false positive.
                    match self.try_read_buf(&mut data) {
                        Ok(in_bytes) => {
                            if in_bytes == data.len() {
                                return Ok(data);
                            } else {
                                fail = format!("Expected {} bytes, got {}", data.len(), in_bytes);
                            }
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            time::sleep(Duration::from_millis(10)).await;
                            continue;
                        }
                        Err(e) => {
                            return Err(e.into());
                        }
                    }
                    if fail.len() > 0 {
                        eprintln!("{fail}");
                    }
                }
                return Err(anyhow!("{fail}"));
            }

            async fn write_bytes(&self, data: &[u8]) -> Result<usize> {
                let mut fail = String::new();
                for _ in 0..3 {
                    // Wait for the socket to be readable
                    self.writable().await?;

                    // Try to read data, this may still fail with `WouldBlock`
                    // if the readiness event is a false positive.
                    match self.try_write(data) {
                        Ok(out_bytes) => {
                            if out_bytes == data.len() {
                                return Ok(data.len());
                            } else {
                                fail =
                                    format!("Wrote {} bytes, only sent {}", data.len(), out_bytes);
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            time::sleep(Duration::from_millis(10)).await;
                            continue;
                        }
                        Err(e) => {
                            return Err(e.into());
                        }
                    }
                    if fail.len() > 0 {
                        eprintln!("{fail}");
                    }
                }
                if fail.len() > 0 {
                    return Err(anyhow!("{fail}"));
                } else {
                    Ok(data.len())
                }
            }
        }
    };
}

pipe_extensions!(NamedPipeClient);
pipe_extensions!(NamedPipeServer);

fn create_dummy_pubkey() -> SSHIdentity {
    let privkey = create_dummy_privatekey();
    let comment = Some("ass@ass.com".to_string());
    let mut pubkey = privkey.pubkey.clone();
    pubkey.comment = comment;
    let identity = Identity::PublicKey(pubkey);
    SSHIdentity {
        identity,
        private_key: Some(privkey),
        constraints: None,
    }
}

fn create_dummy_certificate() -> SSHIdentity {
    // let private_key = create_dummy_privatekey();
    // let ssh_pubkey = private_key.pubkey.clone();
    // let cert = Certificate::builder(&ssh_pubkey, CertType::User, &private_key.pubkey)
    //     .unwrap()
    //     .serial(0xFEFEFEFEFEFEFEFE)
    //     .key_id("key_id")
    //     .principal("obelisk")
    //     .valid_after(0)
    //     .valid_before(0xFFFFFFFFFFFFFFFF)
    //     .set_extensions(Certificate::standard_extensions())
    //     .sign(&private_key)
    //     .unwrap();
    let mut cert = Certificate::from_string("ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgob/qztyiUSbY3dYi5PIp4P48PjdFTpHz0cCggiH66rcAAAADAQABAAABAQDNj4Fk8zjzYPkVQ5t5BFruLSFPK4CY7kjRb3MMIX+tv/W8w6E6x5wLwU9URpDJoK9tKNDXRHWertRobl+lm1WuGf9TVUSj8JybMoF24K+UkmKdO7fUbew3z0kkv/wOhLI5IAw/nLQKDrO/21rCYT+VrOh65yeZk85kzgOKGGr0Vp2d9Tg2SfNhOw9h6/jZS5i3hPMYMs4H/VuDA0Inlc+RjpANoRJURUQs0rkDFB3iwYvZsfep1/YGFVmRM0znXDknKyj7V3hmOwEZp0LlSVpR5o8LBwcr50nMQkxaRdWhi75iXobKBFgbMuBTsFHjZO9s9eoGTGB2NPM65/3x0EQx/v7+/v7+/v4AAAABAAAABmtleV9pZAAAAAsAAAAHb2JlbGlzawAAAAAAAAAA//////////8AAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAAAAABFwAAAAdzc2gtcnNhAAAAAwEAAQAAAQEAzY+BZPM482D5FUObeQRa7i0hTyuAmO5I0W9zDCF/rb/1vMOhOsecC8FPVEaQyaCvbSjQ10R1nq7UaG5fpZtVrhn/U1VEo/CcmzKBduCvlJJinTu31G3sN89JJL/8DoSyOSAMP5y0Cg6zv9tawmE/lazoeucnmZPOZM4Dihhq9FadnfU4NknzYTsPYev42UuYt4TzGDLOB/1bgwNCJ5XPkY6QDaESVEVELNK5AxQd4sGL2bH3qdf2BhVZkTNM51w5Jyso+1d4ZjsBGadC5UlaUeaPCwcHK+dJzEJMWkXVoYu+Yl6GygRYGzLgU7BR42TvbPXqBkxgdjTzOuf98dBEMQAAARQAAAAMcnNhLXNoYTItNTEyAAABAHHtKXUrGAARR0icVbLWC9EBmn+XjL708Qm7orRf7OyJlcofe4rOBPw+/yh7PtD4Ff55BJOabwV7Eto7hykDQUNxLIum3ayZKLtr9dKU929JZex3pJSMS4L1/lqpXRGwzMqrcIQQA2A4B+3QzoX5yJ2w5cEusktK+A22AvqmZdzHRqEy6W1Q2wOct5myEOGGpFP2BHJ9vvHb6SvAAXu2H72DFuEwdcLZALgxtcwbTowJboWeXu2rfOGunF8xuwDPC5BeYRqybwbxVammx/kzgU7d6pn79v9c1yrC3Gp7FDgxgQXB5HvatmtefGmcBslsWIva2Q6HeRWxF2L1kMnHGpM= jjd@jjdpc").unwrap();
    cert.comment = Some("ass@ass.com".to_string());
    SSHIdentity {
        identity: Identity::Certificate(cert),
        private_key: Some(create_dummy_privatekey()),
        constraints: None,
    }
}

fn create_dummy_privatekey() -> PrivateKey {
    let mut private_key = PrivateKey::from_string(concat!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "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\n",
        "dIttV4tGtzrBrkibowAAAAlqamRAampkcGM=\n",
        "-----END OPENSSH PRIVATE KEY-----\n",
    ))
    .unwrap();
    private_key.comment = "ass@ass.com".to_string();
    private_key
}

struct SSHIdentity {
    pub identity: Identity,
    pub private_key: Option<PrivateKey>,
    pub constraints: Option<Vec<KeyConstraint>>,
}

impl PartialEq for SSHIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.identity.into_blob() == other.identity.into_blob()
    }
}

impl Eq for SSHIdentity {}

impl core::hash::Hash for SSHIdentity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.identity.into_blob().hash(state);
    }
}

impl SSHIdentity {
    fn from_identity(identity: Identity) -> Self {
        SSHIdentity {
            identity,
            private_key: None,
            constraints: None,
        }
    }
}



// GetUserSID Gets the SID of the current user.
// fn GetUserSID() -> Result<SID> {

// 	let token = GetCurrentProcessToken();
// 	let user = token.GetTokenUser();

// 	return user.User.Sid
// }

// // GetHandleSID Gets SID for the given handle
// fn GetHandleSID(window: HWND) -> Result<SID> {
// 	security_descriptor = GetSecurityInfo(h, SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
// 	if err != nil {
// 		return nil, err
// 	}

// 	sid, _, err := securityDescriptor.Owner()
// 	if err != nil {
// 		return nil, err
// 	}

// 	return sid, nil
// }

// // GetDefaultSID Returns the default (Security Identifier) SID for the current user.
// fn GetDefaultSID() -> Result<SID> {
// 	let proc = CurrentProcess();
// 	return GetHandleSID(proc)
// }
