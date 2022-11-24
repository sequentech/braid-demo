#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use serde::Serialize;

use braid::chacha20poly1305::{
    aead::{KeyInit},
    ChaCha20Poly1305,
};

use std::{collections::HashSet, sync::Mutex};
use std::iter::FromIterator;
use std::marker::PhantomData;

use braid::strand::backend::ristretto::RistrettoCtx;
use braid::strand::elgamal::Ciphertext;
use braid::strand::serialization::StrandSerialize;
use braid::strand::signature::{StrandSignaturePk, StrandSignatureSk};

use braid::protocol2::artifact::{Configuration};
use braid::protocol2::board::RemoteBoard;
use braid::protocol2::message::Message;
use braid::protocol2::predicate::PublicKeyHash;
use braid::protocol2::trustee::ProtocolManager;
use braid::protocol2::trustee::Trustee;
use braid::strand::context::Ctx;
use tauri::State;

// Learn more about Tauri commands at https://tauri.app/v1/guides/features/command
#[tauri::command]
async fn step(state: State<'_, ContextState<RistrettoCtx>>, active: &str) -> Result<Info, String> {
    

    let mut log = "".to_string();
    let mut context = state.0.lock().unwrap();
    let messages = context.remote.get(0);
    let mut send_messages = vec![];
    
    if active.len() == 0 {
        for t in context.trustees.iter_mut() {
        
            let (messages, _actions) = t.step(messages.clone()).unwrap();
            
            for m in messages.into_iter() {
                send_messages.push(m);
            }
        
        }
        log = format!("Step trustee=all yields {} messages", send_messages.len());
    }
    else {
        let t: usize = active.parse().unwrap();
        if t >= 0 && t < context.trustees.len() {
            let (messages, _actions) = context.trustees[t].step(messages.clone()).unwrap();
            for m in messages.into_iter() {
                send_messages.push(m);
            }
        }
        log = format!("Step for trustee={} yields {} messages", t, send_messages.len());
        
    }
    send(&send_messages, &mut context.remote);

    if let Some(plaintexts) = context.trustees[0].get_plaintexts_nohash(1) {
        let set1: HashSet<[u8;30]> = HashSet::from_iter(plaintexts.0.0);
        let set2: HashSet<[u8;30]> = HashSet::from_iter(context.plaintexts.iter().cloned());

        log = format!("Run complete: plaintexts match = '{}'", set1 == set2);
    }

    context.last_messages= send_messages;

    let info = Info::new(&context, log);
    Ok(info)
    
    // Ok(vec![Row::new(23, "hoho".to_string(), "haha".to_string(), 2323, "hohohoo".to_string())])
}

#[tauri::command]
async fn reset(state: State<'_, ContextState<RistrettoCtx>>, trustees: u8, threshold: usize) -> Result<Info, String> {
    let mut log = format!("Reset: trustees = {}, threshold = {}", trustees, threshold);
    
    let mut context = state.0.lock().unwrap();
    let t = [1, 2, 3, 4, 5, 6, 7, 8];
    let new_context = mk_context(RistrettoCtx, trustees, &t[0..threshold]);
    

    context.trustees = new_context.trustees;
    context.selected = new_context.selected;
    context.trustee_pks = new_context.trustee_pks;
    context.protocol_manager = new_context.protocol_manager;
    context.cfg = new_context.cfg;
    context.remote = new_context.remote;
    context.last_messages = new_context.last_messages;
    context.plaintexts = new_context.plaintexts;
    
    let info = Info::new(&context, log);
    Ok(info)
}

#[tauri::command]
async fn ballots(state: State<'_, ContextState<RistrettoCtx>>, count: usize) -> Result<Info, String> {
    
    let mut log = "".to_string();
    
    let mut context = state.0.lock().unwrap();
    
    let pk_element_ = context.trustees[0].get_dkg_public_key_nohash();
    if pk_element_.is_some() {
        let pk_element = pk_element_.unwrap().pk;
        let pk = braid::strand::elgamal::PublicKey::from_element(&pk_element, &context.ctx);
        let pk_h = braid::strand::util::hash(&pk.strand_serialize());

        let ps: Vec<[u8;30]> = (0..count).map(|_| context.ctx.rnd_plaintext()).collect();
        let ballots: Vec<Ciphertext<RistrettoCtx>> = ps
            .iter()
            .map(|p| {
                let encoded = context.ctx.encode(&p).unwrap();
                pk.encrypt(&encoded)
            })
            .collect();

        let ballot_batch = braid::protocol2::artifact::Ballots::new(ballots, context.selected, &context.cfg);
        let message = braid::protocol2::message::Message::ballots_msg(
            &context.cfg,
            1,
            &ballot_batch,
            PublicKeyHash(braid::protocol2::Hash::from(&pk_h)),
            &context.protocol_manager,
        );
        if context.plaintexts.len() == 0 {
            context.plaintexts = ps;
            context.last_messages = vec![message.clone()];
            context.remote.add(message);
            log = format!("Added {} ballots", count);
        }
        else {
            log = "Ballots already added".to_string();
        }
        
    }
    else {
        log = "No pk yet".to_string();
    }
    
    let info = Info::new(&context, log);
    Ok(info)
}

fn send(messages: &Vec<Message>, remote: &mut RemoteBoard) {
    for m in messages.iter() {
        remote.add(m.clone());
    }
}


fn main() {
    braid::util::init_log(true);
    
    let n_trustees = 2;
    let threshold = 2;
    let t = [1, 2, 3, 4, 5, 6, 7, 8];
    
    let context = Mutex::new(mk_context(RistrettoCtx, n_trustees, &t[0..threshold]));
    
    
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![step, reset, ballots])
        .manage(ContextState(context))
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn mk_context<C: Ctx>(ctx: C, n_trustees: u8, threshold: &[usize]) -> AppContext<C> {
    let mut csprng = braid::strand::rnd::StrandRng;
    let session_id = 0;
    let selected = get_selected(threshold);

    let pmkey: StrandSignatureSk = StrandSignatureSk::new(&mut csprng);
    let pm: ProtocolManager<C> = ProtocolManager {
        signing_key: pmkey,
        phantom: PhantomData,
    };

    let trustees: Vec<Trustee<C>> = (0..n_trustees)
        .into_iter()
        .map(|_| {
            let kp = StrandSignatureSk::new(&mut csprng);
            let encryption_key = ChaCha20Poly1305::generate_key(&mut braid::chacha20poly1305::aead::OsRng);
            Trustee::new(kp, encryption_key)
        })
        .collect();

    let trustee_pks: Vec<StrandSignaturePk> = trustees
        .iter()
        .map(|t| StrandSignaturePk::from(&t.signing_key))
        .collect();

    let cfg = Configuration::<C>::new(
        0,
        StrandSignaturePk::from(&pm.signing_key),
        trustee_pks.clone(),
        threshold.len(),
        PhantomData,
    );

    let mut remote = RemoteBoard::new(session_id);
    let message = Message::bootstrap_msg(&cfg, &pm);
    let last_messages = vec![message.clone()];
    remote.add(message);

    AppContext {
        ctx,
        cfg,
        session_id,
        protocol_manager: pm,
        trustees,
        selected,
        trustee_pks,
        remote,
        plaintexts: vec![],
        last_messages
    }
}

pub struct AppContext<C: Ctx> {
    pub ctx: C,
    pub cfg: Configuration<C>,
    pub session_id: u128,
    pub protocol_manager: ProtocolManager<C>,
    pub trustees: Vec<Trustee<C>>,
    pub selected: [usize; 12],
    pub trustee_pks: Vec<StrandSignaturePk>,
    pub remote: RemoteBoard,
    pub plaintexts: Vec<C::P>,
    pub last_messages: Vec<Message>
}

pub struct ContextState<C: Ctx>(Mutex<AppContext<C>>);

pub fn get_selected(input: &[usize]) -> [usize; 12] {
    let mut selected = [braid::protocol2::datalog::NULL_TRUSTEE; 12];
    selected[0..input.len()].clone_from_slice(input);
    selected
}

#[derive(Serialize, Debug)]
pub struct Info {
    messages: Vec<Msg>,
    trustee_rows: Vec<TrusteeRow>,
    last_messages: Vec<Msg>,
    log: String,
}
impl Info {
    pub fn new(context: &AppContext<RistrettoCtx>, log: String) -> Info {
        let ms = context.remote.messages.clone();
        let lms = context.last_messages.clone();
        let messages: Vec<Msg> = ms.iter().enumerate().map(|m| {
            Msg::from(m.0, &m.1, &context.cfg)
        }).collect();

        let trustee_rows: Vec<TrusteeRow> =  context.trustees.iter().enumerate().map(|t| {
            TrusteeRow::from(t.0, &t.1, &context.cfg)
        }).collect();


        let last_messages: Vec<Msg> = lms.iter().enumerate().map(|m| {
            Msg::from(m.0, &m.1, &context.cfg)
        }).collect();

        
        let ret = Info {
            messages,
            trustee_rows,
            last_messages,
            log
        };

        ret
    }
}
#[derive(Serialize, Debug)]
struct Msg {
    pub id: usize,
    pub type_: String,
    pub sender: usize,
    pub artifact: bool,
}
impl Msg {
    pub fn from(id: usize, m: &Message, cfg: &Configuration<RistrettoCtx>) -> Msg {
        let type_ = m.statement.type_.to_string();
        let sender = cfg.get_trustee_position(&m.signer_key).unwrap();
        Msg {
            id,
            type_,
            sender,
            artifact: m.artifact.is_some(),
        }
    }
}

#[derive(Serialize, Debug)]
struct TrusteeRow {
    pub id: usize,
    pub position: usize,
    pub statement_data: String,
    pub artifact_data: String,
}
impl TrusteeRow {
    pub fn from(id: usize, t: &Trustee<RistrettoCtx>, cfg: &Configuration<RistrettoCtx>) -> TrusteeRow {
        let mut data1: Vec<String> = t.copy_local_board()
                .statements
                .keys()
                .map(|k| format!("{}-{}", k.type_.to_string(), k.signer_position.to_string()))
                .collect();
        let mut data2: Vec<String> = t.copy_local_board()
                .artifacts
                .keys()
                .map(|k| {
                    format!(
                        "{}-{}",
                        k.parameter.to_string(),
                        k.statement_entry.signer_position.to_string()
                    )
                })
                .collect();

        data1.sort();
        data2.sort();
        let statement_data: String = data1.join(" ");
        let artifact_data: String = data2.join(" ");

        let position = cfg.get_trustee_position(&t.get_pk()).unwrap();
        TrusteeRow {
            id, 
            position,
            statement_data,
            artifact_data,
        }
    }
}