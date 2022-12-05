use std::borrow::Cow;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use sshcerts::{
    ssh::{Fingerprint, KeyType, KeyTypeKind, Reader, Writer},
    Certificate, PrivateKey, PublicKey,
};

#[allow(non_camel_case_types)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, IntoPrimitive, Default)]
#[repr(u8)]
pub enum ClientCode {
    SSH_AGENTC_REQUEST_IDENTITIES = 11,
    SSH_AGENTC_SIGN_REQUEST = 13,
    SSH_AGENTC_ADD_IDENTITY = 17,
    SSH_AGENTC_REMOVE_IDENTITY = 18,
    SSH_AGENTC_REMOVE_ALL_IDENTITIES = 19,
    SSH_AGENTC_ADD_ID_CONSTRAINED = 25,
    SSH_AGENTC_ADD_SMARTCARD_KEY = 20,
    SSH_AGENTC_REMOVE_SMARTCARD_KEY = 21,
    SSH_AGENTC_LOCK = 22,
    SSH_AGENTC_UNLOCK = 23,
    SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26,
    SSH_AGENTC_EXTENSION = 27,
    #[default]
    SSH_AGENTC_INVALID = 0,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, IntoPrimitive, Default)]
#[repr(u8)]
pub enum AgentReplyCode {
    SSH_AGENT_FAILURE = 5,
    SSH_AGENT_SUCCESS = 6,
    SSH_AGENT_EXTENSION_FAILURE = 28,
    SSH_AGENT_IDENTITIES_ANSWER = 12,
    SSH_AGENT_SIGN_RESPONSE = 14,
    #[default]
    SSH_AGENT_INVALID = 0,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, IntoPrimitive, Default, Clone)]
#[repr(u8)]
pub enum ConstraintType {
    SSH_AGENT_CONSTRAIN_LIFETIME = 1,
    // byte                    SSH_AGENT_CONSTRAIN_LIFETIME
    // uint32                  seconds
    SSH_AGENT_CONSTRAIN_CONFIRM = 2,
    // byte                    SSH_AGENT_CONSTRAIN_CONFIRM // no bytes, just requires user interaction for private key operations
    SSH_AGENT_CONSTRAIN_EXTENSION = 255,
    // byte                     SSH_AGENT_CONSTRAIN_EXTENSION
    // byte[]                   // Extension specific data
    #[default]
    SSH_AGENT_CONSTRAIN_INVALID = 0,
}

const AGENT_FAIL_MESSAGE: Cow<[u8]> =
    Cow::Borrowed(&[0, 0, 0, 1, AgentReplyCode::SSH_AGENT_FAILURE as _]);
const AGENT_SUCCESS_MESSAGE: Cow<[u8]> =
    Cow::Borrowed(&[0, 0, 0, 1, AgentReplyCode::SSH_AGENT_SUCCESS as _]);
const AGENT_EXTENSION_FAIL_MESSAGE: Cow<[u8]> =
    Cow::Borrowed(&[0, 0, 0, 1, AgentReplyCode::SSH_AGENT_EXTENSION_FAILURE as _]);

#[derive(Clone, Debug)]
pub struct KeyConstraint {
    ctype: ConstraintType,
    cbytes: Option<Vec<u8>>,
}

trait TypeCode {}

impl TypeCode for ConstraintType {}
impl TypeCode for AgentReplyCode {}
impl TypeCode for ClientCode {}

#[allow(non_camel_case_types)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, IntoPrimitive, Default)]
#[repr(u32)]
enum SignatureFlag {
    SSH_AGENT_RSA_SHA2_256 = 2,
    SSH_AGENT_RSA_SHA2_512 = 4,
    #[default]
    SSH_AGENT_FLAG_INVALID = 0,
}

pub struct AgentServer<T> {
    agent: T,
}

impl<T: SSHAgent + Sync + Send> AgentServer<T> {
    pub fn new(agent: T) -> Self {
        Self { agent }
    }

    pub async fn message<'a>(&'a mut self, data: &'a [u8]) -> Cow<'a, [u8]> {
        match server_message(data, &mut self.agent).await {
            Ok(message) => message,
            Err(err) => {
                println!("{}", err);
                Cow::Borrowed(&AGENT_FAIL_MESSAGE)
            }
        }
    }
}

fn write_payload(payload: &[u8]) -> Vec<u8> {
    let mut p_writer = Writer::new();
    p_writer.write_bytes(payload);
    p_writer.into_bytes()
}

async fn server_message<'a, A: SSHAgent>(
    data: &'a [u8],
    agent: &'a mut A,
) -> Result<Cow<'a, [u8]>> {
    let length = bytes_to_u32_as_usize(&data[0..4])?;
    let actual_size = data.len() - 4;
    if actual_size != length {
        return Err(anyhow!(
            "Invalid client message: reported {length} but sent {actual_size}"
        ));
    }
    if length == 0 {
        // Are you there, agent?
        return Ok(AGENT_SUCCESS_MESSAGE); // Why yes, I am!
    }
    let type_code = data[4];

    let dummy = Vec::new();

    let mtype = ClientCode::try_from(type_code).unwrap_or_default();

    let mut dc = Vec::new();
    dc.push(KeyConstraint {
        ctype: ConstraintType::SSH_AGENT_CONSTRAIN_CONFIRM,
        cbytes: None,
    });
    let dummy_constraints = Some(dc);

    match mtype {
        ClientCode::SSH_AGENTC_REQUEST_IDENTITIES => {
            // byte                    SSH_AGENT_IDENTITIES_ANSWER
            // uint32                  nkeys // Where "nkeys" indicates the number of keys to follow
            // Following the preamble are zero or more keys, each encoded as:
            // string                  key blob
            // string                  comment
            let idreply = RequestIdentitiesResponse(agent.request_identities().await?).into_bytes();
            Ok(Cow::Owned(idreply))
        }
        ClientCode::SSH_AGENTC_SIGN_REQUEST => {
            // byte                    SSH_AGENTC_SIGN_REQUEST
            // string                  key blob
            // string                  data
            // uint32                  flags // These flags form a bit field by taking the logical OR of zero or more flags
            // reply:
            // byte                    SSH_AGENT_SIGN_RESPONSE
            // string                  signature
            let signrequest = SignRequest::from_bytes(data)?;
            let signature = agent
                .sign_message(
                    signrequest.identity,
                    signrequest.message.as_slice(),
                    signrequest.flags,
                )
                .await?;
            Ok(Cow::Owned(SignResponse(signature).into_bytes()))
        }
        ClientCode::SSH_AGENTC_ADD_IDENTITY => {
            // byte                    SSH_AGENTC_ADD_IDENTITY
            // string                  key type
            // byte[]                  key contents
            // string                  key comment
            let private_key = PrivateKey::from_bytes(&data[5..])?;
            agent.add_id(private_key, None).await?;
            Ok(AGENT_SUCCESS_MESSAGE)
        }
        ClientCode::SSH_AGENTC_REMOVE_IDENTITY => {
            // byte                    SSH_AGENTC_REMOVE_IDENTITY
            // string                  key blob
            let identity = Identity::from_bytes(&data[5..])?;
            agent.remove(identity).await?;
            Ok(AGENT_SUCCESS_MESSAGE)
        }
        ClientCode::SSH_AGENTC_REMOVE_ALL_IDENTITIES => {
            agent.remove_all().await?;
            Ok(AGENT_SUCCESS_MESSAGE)
        }
        ClientCode::SSH_AGENTC_ADD_ID_CONSTRAINED => {
            // byte                    SSH_AGENTC_ADD_ID_CONSTRAINED
            // string                  type
            // byte[]                  contents
            // string                  comment
            // constraint[]            constraints
            let private_key = PrivateKey::from_bytes(&data[5..])?;
            // A number of constraints and may be used in the constrained variants
            // of the key add messages.  Each constraint is represented by a type
            // byte followed by zero or more value bytes.

            // Zero or more constraints may be specified when adding a key with one
            // of the *_CONSTRAINED requests.  Multiple constraints are appended
            // consecutively to the end of the request:

            //     byte                    constraint1_type
            //     byte[]                  constraint1_data
            //     byte                    constraint2_type
            //     byte[]                  constraint2_data
            //     ....
            //     byte                    constraintN_type
            //     byte[]                  constraintN_data

            agent.add_id(private_key, dummy_constraints).await?;
            Ok(AGENT_SUCCESS_MESSAGE)
        }
        ClientCode::SSH_AGENTC_ADD_SMARTCARD_KEY => {
            // byte                    SSH_AGENTC_ADD_SMARTCARD_KEY
            // string                  id
            // string                  PIN
            // Here "id" is an opaque identifier for the hardware token and "PIN" is
            // an optional password on PIN to unlock the key.  The interpretation of
            // "id" is not defined by the protocol but is left solely up to the
            // agent.
            agent
                .add_sc_key(b"dummy_identity", Some(&dummy), None)
                .await?;
            Ok(AGENT_SUCCESS_MESSAGE)
        }
        ClientCode::SSH_AGENTC_REMOVE_SMARTCARD_KEY => {
            // byte                    SSH_AGENTC_REMOVE_SMARTCARD_KEY
            // string                  reader id // "an opaque identifier for the smartcard reader"
            // string                  PIN // optional password or PIN (not typically used)
            agent.remove_sc_key(b"dummy_identity").await?;
            Ok(AGENT_SUCCESS_MESSAGE)
        }
        ClientCode::SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED => {
            // byte                    SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED
            // string                  id
            // string                  PIN
            // constraint[]            constraints
            // Here "id" is an opaque identifier for the hardware token and "PIN" is
            // an optional password on PIN to unlock the key.  The interpretation of
            // "id" is not defined by the protocol but is left solely up to the
            // agent.
            agent
                .add_sc_key(b"dummy_identity", Some(&dummy), dummy_constraints)
                .await?;
            Ok(AGENT_SUCCESS_MESSAGE)
        }
        ClientCode::SSH_AGENTC_LOCK => {
            // byte                    SSH_AGENTC_LOCK
            // string                  passphrase
            agent.lock(&data[5..])?;
            Ok(AGENT_SUCCESS_MESSAGE)
        }
        ClientCode::SSH_AGENTC_UNLOCK => {
            // byte                    SSH_AGENTC_UNLOCK
            // string                  passphrase
            agent.unlock(&data[5..]).await?;
            Ok(AGENT_SUCCESS_MESSAGE)
        }
        ClientCode::SSH_AGENTC_EXTENSION => {
            // byte                    SSH_AGENTC_EXTENSION
            // string                  extension type
            // byte[]                  extension contents
            let supported_extensions = agent.extension_query();

            let mut reader = Reader::new(&data[5..]);
            let extension_name = reader
                .read_string()
                .map_err(|e| anyhow!("Received an invalid extension name: {e}"))?;
            println!("{extension_name}");
            if extension_name == "version" {
                return Ok(Cow::Borrowed(agent.version().as_bytes()));
            }
            if extension_name == "query" {
                //    byte                    SSH_AGENT_SUCCESS
                //    string[]                extension type
                let reply = if let Some(extension_names) = supported_extensions {
                    let mut writer = Writer::new();
                    writer.write_raw_bytes(&[AgentReplyCode::SSH_AGENT_SUCCESS as _]);
                    extension_names.iter().for_each(|e| {
                        writer.write_string(e);
                    });
                    Cow::Owned(writer.into_bytes())
                } else {
                    AGENT_SUCCESS_MESSAGE
                };

                return Ok(reply);
            }
            // Only call the extension if the agent says that it actually supports that extension
            if let Some(extension_names) = supported_extensions {
                if extension_names.contains(&extension_name) {
                    let extension_data = &data[reader.get_offset()..];
                    if let Ok(extension_reply) =
                        agent.extension(&extension_name, extension_data).await
                    {
                        if let Some(extension_data) = extension_reply {
                            let mut writer = Writer::new();
                            writer.write_bytes(&extension_data);
                            let extension_return = writer.as_bytes();
                            return Ok(Cow::Owned(extension_return.to_vec()));
                        } else {
                            return Ok(AGENT_SUCCESS_MESSAGE);
                        }
                    } else {
                        // Generic extension failure
                        return Ok(AGENT_EXTENSION_FAIL_MESSAGE);
                    }
                } else {
                    // We don't support the requested extension
                    return Err(anyhow!("Extension {extension_name} is not supported"));
                }
            };
            Ok(AGENT_SUCCESS_MESSAGE)
        }
        ClientCode::SSH_AGENTC_INVALID => Err(anyhow!("Unsupported Operation Code: {type_code}")),
    }
}

#[derive(Debug)]
pub enum Identity {
    PublicKey(PublicKey),
    Certificate(Certificate),
}

impl Identity {
    pub fn set_comment(&mut self, comment: String) {
        match self {
            Identity::PublicKey(pk) => pk.comment = Some(comment),
            Identity::Certificate(cert) => cert.comment = Some(comment),
        }
    }
    pub fn get_comment(&self) -> Option<&str> {
        match self {
            Identity::PublicKey(pk) => pk.comment.as_deref(),
            Identity::Certificate(cert) => cert.comment.as_deref(),
        }
    }
    pub fn fingerprint(&self) -> Fingerprint {
        match self {
            Identity::PublicKey(pk) => pk.fingerprint(),
            Identity::Certificate(cert) => cert.key.fingerprint(),
        }
    }
    pub fn into_blob(&self) -> Vec<u8> {
        match self {
            Identity::PublicKey(pk) => pk.encode(),
            Identity::Certificate(cert) => cert.serialized.clone(),
        }
    }
    fn into_wire_blobs(&self, blobs: &mut Vec<Vec<u8>>) {
        match self {
            Identity::PublicKey(pubkey) => {
                let mut writer = Writer::new();
                writer.write_bytes(&pubkey.encode());
                writer.write_string(&pubkey.comment.clone().unwrap_or_default());
                blobs.push(writer.into_bytes());
            }
            Identity::Certificate(cert) => {
                let mut writer = Writer::new();
                writer.write_bytes(&cert.serialized);
                writer.write_string(&cert.comment.clone().unwrap_or_default());
                blobs.push(writer.into_bytes());
                let mut writer = Writer::new();
                writer.write_bytes(&cert.key.encode());
                writer.write_string(&cert.comment.clone().unwrap_or_default());
                blobs.push(writer.into_bytes());
            }
        }
    }
    fn from_bytes(blob: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(&blob);
        let kt_name = reader.read_string()?;
        let kt = KeyType::from_name(&kt_name)?;
        reader.read_bytes()?; // Actual key data that we already captured above
        match kt.kind {
            KeyTypeKind::Rsa | KeyTypeKind::Ed25519 | KeyTypeKind::Ecdsa => {
                let pubkey = PublicKey::from_bytes(&blob)?;
                Ok(Identity::PublicKey(pubkey))
            }
            KeyTypeKind::RsaCert | KeyTypeKind::Ed25519Cert | KeyTypeKind::EcdsaCert => {
                let cert = Certificate::from_bytes(blob)?;
                Ok(Identity::Certificate(cert))
            }
        }
    }
}

// Represents either an ssh public key or an ssh certificate

pub struct SignRequest {
    pub identity: Identity,
    pub message: Vec<u8>,
    pub flags: u32, // These flags form a bit field by taking the logical OR of zero or more flags
}

impl SignRequest {
    pub fn into_bytes(self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.write_raw_bytes(&[ClientCode::SSH_AGENTC_SIGN_REQUEST.into()]);
        writer.write_bytes(&self.identity.into_blob());
        writer.write_bytes(self.message.as_slice());
        writer.write_u32(self.flags);
        write_payload(&writer.into_bytes())
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        let mut reader = Reader::new(data);
        let _length = reader.read_u32()?; // Message length
        let _mtype = ClientCode::try_from(reader.read_raw_bytes(1)?[0])?;
        let blob = reader.read_bytes()?;
        let identity = Identity::from_bytes(&blob)?;
        let message = reader.read_bytes()?;
        let flags = if data.len() >= (reader.get_offset() + 4) as _ {
            reader.read_u32()?
        } else {
            0
        };
        Ok(Self {
            identity,
            message,
            flags,
        })
    }
}

#[derive(Debug)]
pub struct SignResponse(pub Vec<u8>);

impl SignResponse {
    pub fn into_bytes(self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.write_raw_bytes(&[AgentReplyCode::SSH_AGENT_SIGN_RESPONSE.into()]);
        writer.write_bytes(self.0.as_slice());
        write_payload(&writer.into_bytes())
    }
    pub fn from_bytes(data: Vec<u8>) -> Result<Self>
    where
        Self: Sized,
    {
        let mut reader = Reader::new(data.as_slice());
        let _length = reader.read_u32()?; // Message length
        let _mtype = AgentReplyCode::try_from(reader.read_raw_bytes(1)?[0])?;
        let signature = reader.read_bytes()?;
        Ok(Self(signature))
    }
    // pub fn from_signature(signature: Vec<u8>) -> Self {
    //     let mut writer = Writer::new();
    //     writer.write_raw_bytes(&[AgentReplyCode::SSH_AGENT_SIGN_RESPONSE.into()]);
    //     writer.write_bytes(signature.as_slice());
    //     Self(writer.into_bytes())
    // }
}

pub struct RequestIdentitiesResponse<'a>(pub Vec<&'a Identity>);

impl<'a> RequestIdentitiesResponse<'a> {
    pub fn into_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.write_raw_bytes(&[AgentReplyCode::SSH_AGENT_IDENTITIES_ANSWER.into()]);
        let mut blobs = Vec::new();
        self.0.iter().for_each(|i| {
            i.into_wire_blobs(&mut blobs);
        });
        writer.write_u32(blobs.len() as _); // nkeys
        blobs.into_iter().for_each(|b| {
            writer.write_raw_bytes(&b);
        });
        write_payload(&writer.into_bytes())
    }

    pub fn from_bytes(data: Vec<u8>) -> Result<Vec<Identity>> {
        let mut reader = Reader::new(data.as_slice());
        reader.set_offset(6)?;
        // let _length = reader.read_u32()?; // Message length
        // let _mtype = AgentReplyCode::try_from(reader.read_raw_bytes(1)?[0])?;
        let nkeys = reader.read_u32()?; // Number of keys the agent has
        let mut identities = Vec::new();
        for _ in 0..nkeys {
            let blob = reader.read_bytes()?;
            let mut identity = Identity::from_bytes(&blob)?;
            let comment = reader.read_string().unwrap_or_default();
            if comment.len() > 0 {
                identity.set_comment(comment)
            };
            identities.push(identity)
        }
        return Ok(identities);
    }
}

pub fn bytes_to_u32_as_usize(data: &[u8]) -> Result<usize> {
    if data.len() < 4 {
        return Err(anyhow!("Can't read length value, input data too short"));
    }
    let length = u32::from_be_bytes(data[0..4].try_into()?) as _;
    Ok(length)
}

#[async_trait]
pub trait SSHAgent {
    // List agent identities
    async fn request_identities(&self) -> Result<Vec<&Identity>>;
    // Sign a message with the private key belonging to the identity
    async fn sign_message(&self, identity: Identity, data: &[u8], flags: u32) -> Result<Vec<u8>>; //Result<CryptoVec>;
                                                                                                  // Add an identity
    async fn add_id(
        &mut self,
        private_key: PrivateKey,
        constraints: Option<Vec<KeyConstraint>>,
    ) -> Result<()>;
    // Remove a single identity
    // Your implementation should return an error condition if it can't delete the private key for whatever reason, including if it can't find it
    async fn remove(&mut self, identity: Identity) -> Result<()>;
    // Remove all identities
    // Your implementation should return an error condition if it can't remove all identities
    async fn remove_all(&mut self) -> Result<()>;
    // Add a smartcard key with optional pin and optional usage constraints
    async fn add_sc_key(
        &mut self,
        id: &[u8],
        pin: Option<&[u8]>,
        constraints: Option<Vec<KeyConstraint>>,
    ) -> Result<()>;
    // Remove a smartcard key
    async fn remove_sc_key(&mut self, id: &[u8]) -> Result<()>;
    // Lock the agent; the draft RFC says that your implementation must at least block all private key operations, and may optionally block anything else.
    fn lock(&mut self, passphrase: &[u8]) -> Result<()>;
    // Unlock the agent
    async fn unlock(&mut self, passphrase: &[u8]) -> Result<()>;
    // Call an agent extension; simply return an error if your implementation has no extensions. You may also return None if you support the extension that was called for but have no data to return other than a standard "success" reply.
    async fn extension(&mut self, name: &str, data: &[u8]) -> Result<Option<Vec<u8>>>;
    // Query extensions. By using this library, you implicitly support the "query" extension according to the spec, even if you otherwise don't support extensions at all.
    fn extension_query(&self) -> Option<&Vec<String>>;
    // Simply return a version string
    fn version(&self) -> &str;
}
