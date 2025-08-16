//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.
//! In this example, you will see the use of the `launcher` feature.
//! The `launcher` will spawn new processes for each cpu core.
use std::{cell::RefCell, env, fs, path::Path, rc::Rc};

use autarkie::{fuzzer::{context::{Context, MutationMetadata}, mutators::{iterable_pop::AutarkieIterablePopMutator, random::AutarkieRandomMutator, splice::{AutarkieSpliceMutator, SPLICE_STACK}, splice_append::AutarkieSpliceAppendMutator}, stages::{binary_mutator::AutarkieBinaryMutatorStage, generate::GenerateStage, minimization::MinimizationStage, mutating::MutatingStageWrapper, mutational::AutarkieMutationalStage, recursive_minimization::RecursiveMinimizationStage, stats::{AutarkieStats, StatsStage}}}, tree::Node, DepthInfo, Visitor};
use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, Testcase}, events::{ClientDescription, EventConfig, Launcher, LlmpRestartingEventManager}, executors::{inprocess::InProcessExecutor, ExitKind}, feedback_and_fast, feedback_or, feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback}, fuzzer::{Fuzzer, StdFuzzer}, inputs::Input, monitors::MultiMonitor, observers::{CanTrack, HitcountsMapObserver, TimeObserver}, prelude::{powersched::PowerSchedule, BacktraceObserver, I2SRandReplace, NewHashFeedback, ShadowExecutor, StdWeightedScheduler}, stages::{IfStage, ShadowTracingStage}, state::{HasCorpus, HasCurrentTestcase, StdState}, Error, ExecutesInput, HasMetadata
};
use libafl_bolts::{
    core_affinity::Cores, current_nanos, rands::StdRand, shmem::{ShMemProvider, StdShMemProvider}, tuples::tuple_list, HasLen
};
use libafl_targets::{libfuzzer_initialize, libfuzzer_test_one_input, std_edges_map_observer, CmpLogObserver};
use prost::Message;

use crate::helper_stuff::AutarkieGenerator;

mod helper_stuff;
include!(concat!(env!("OUT_DIR"), "/mod.rs"));

// just copy the (full) type used inside the lpm harness here.
type TargetType = tint::cmd::fuzz::ir::pb::Root;


const INITIAL_GENERATED_INPUTS: usize = 100;
const ITERATE_DEPTH: usize = 5;
const MAX_SUBSPLICE_SIZE: usize = 15;
const STRING_POOL_SIZE: usize = 50;
const GENERATE_DEPTH: usize = 10;
const OUTPUT_DIR: &str = "/tmp/autarkie_tmp/";

/// The main fn, `no_mangle` as it is a C symbol
#[no_mangle]
pub extern "C" fn libafl_main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let total_len = args.len();
    let is_repro = !args.is_empty();

    env_logger::init();
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    let broker_port = 7777;
    let cores = Cores::from(Vec::from_iter(
        if is_repro {0..1} else {0..24}
        //0..1
    ));

    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    let monitor = MultiMonitor::new(|s| println!("{s}"));
    let mut secondary_run_client = |state: Option<_>, mut mgr: LlmpRestartingEventManager<(), _, _, _, _>, client_description: ClientDescription| -> Result<(), Error> {
        
        let is_main_node = client_description.core_id().0 == 0;
        let output_dir = Path::new(OUTPUT_DIR);
        let fuzzer_dir = output_dir.join(format!("{}", client_description.core_id().0));

        fs::create_dir_all(&fuzzer_dir)?;

        
        // Create an observation channel using the coverage map
        let edges_observer =
            HitcountsMapObserver::new(unsafe { std_edges_map_observer("edges") }).track_indices().track_novelties();

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");
        let map_feedback = MaxMapFeedback::new(&edges_observer);

        // do init this here because after constructing feedback map_feedback is moved
        // Initialize Autarkie's visitor
        let mut visitor = Visitor::new(
            current_nanos(),
            DepthInfo {
                generate: GENERATE_DEPTH,
                iterate: ITERATE_DEPTH,
            },
            STRING_POOL_SIZE,
        );
        TargetType::__autarkie_register(&mut visitor, None, 0);


        let _recursive_nodes = visitor.calculate_recursion();
        if is_main_node {
            std::fs::write(
                output_dir.join("type_input_map.json"),
                serde_json::to_string_pretty(visitor.ty_name_map()).expect("invariant"),
            )?;
        }
        if is_main_node {
            std::fs::write(
                output_dir.join("type_generate_map.json"),
                serde_json::to_string_pretty(visitor.ty_generate_map()).expect("invariant"),
            )?;
        }

        let visitor = Rc::new(RefCell::new(visitor));

        let cb = |_fuzzer: &mut _,
              _executor: &mut _,
              state: &mut StdState<_, _, _, _>,
              _event_manager: &mut _|
        -> Result<bool, Error> {
            Ok(state.current_testcase_mut()?.scheduled_count() == 0)
        };

        let splice_mutator = AutarkieSpliceMutator::new(Rc::clone(&visitor), MAX_SUBSPLICE_SIZE);
        let random_mutator = AutarkieRandomMutator::new(Rc::clone(&visitor), MAX_SUBSPLICE_SIZE);
        let splice_append_mutator = AutarkieSpliceAppendMutator::new(Rc::clone(&visitor));

        let minimization_stage = IfStage::new(
            cb,
            tuple_list!(
                MinimizationStage::new(Rc::clone(&visitor), &map_feedback),
                MinimizationStage::new(Rc::clone(&visitor), &map_feedback),
                RecursiveMinimizationStage::new(Rc::clone(&visitor), &map_feedback),
            ),
        );

         // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            map_feedback,
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new(&time_observer),
        );
        let bt_observer =
            BacktraceObserver::owned("BacktraceObserver", libafl::observers::HarnessType::InProcess);

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_and_fast!(
                    CrashFeedback::new(),
                    NewHashFeedback::new(&bt_observer),
                );
        // If not restarting, create a State from scratch
        let mut corpus = InMemoryCorpus::new();

        if is_repro {
            for next_input in args.iter().map(|file_path|  TargetType::from_file(file_path).expect("failed to read input")) {
                let _ = corpus.add(Testcase::new(next_input));
            }
        }
    

        let cmplog_observer = CmpLogObserver::new("cmplog", true);

        let mut state: StdState<_, _, _, _> = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::new(),
                // Corpus that will be evolved, we keep it in memory for performance
                corpus,
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new("./solutions").unwrap(),
                // States of the feedbacks.
                // The feedbacks can report the data that should persist in the State.
                &mut feedback,
                // Same for objective feedbacks
                &mut objective,
            )
            .unwrap()
        });
        println!("We're a client, let's fuzz :)");

        let mut harness = |input: &TargetType| {
            let protobuf_vec = input.encode_to_vec();
            unsafe {libfuzzer_test_one_input(protobuf_vec.as_slice()) };
            ExitKind::Ok
        };


        let context = Context::new(fuzzer_dir.clone(), false);
        state.add_metadata(context);
        state.add_metadata(AutarkieStats::default());
        let schedule = match client_description.core_id().0 % 6 {
        0 => PowerSchedule::explore(),
        1 => PowerSchedule::exploit(),
        2 => PowerSchedule::quad(),
        3 => PowerSchedule::coe(),
        4 => PowerSchedule::lin(),
        5 => PowerSchedule::fast(),
        _ => unreachable!(),
        };

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler =
            StdWeightedScheduler::with_schedule(&mut state, &edges_observer, Some(schedule));


        let tracing = ShadowTracingStage::new();

        let i2s = AutarkieBinaryMutatorStage::new(
        tuple_list!(I2SRandReplace::new()),
        7,
        MutationMetadata::I2S,
        );

        let mut stages = tuple_list!(
            minimization_stage,
            tracing,
            GenerateStage::new(Rc::clone(&visitor)),
            AutarkieMutationalStage::new(
                tuple_list!(
                    splice_append_mutator,
                    random_mutator,
                    splice_mutator,
                    AutarkieIterablePopMutator::new(Rc::clone(&visitor))
                ),
                SPLICE_STACK,
                Rc::clone(&visitor)
            ),
            MutatingStageWrapper::new(i2s, Rc::clone(&visitor)),
            StatsStage::new(fuzzer_dir),
        );


        // The actual target run starts here.
        // Call LLVMFUzzerInitialize() if present.
        if unsafe {libfuzzer_initialize(&Vec::new())} == -1 {
            println!("Warning: LLVMFuzzerInitialize failed with -1");
        }

            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

            let mut executor = ShadowExecutor::new(
                InProcessExecutor::new(
                    &mut harness,
                    tuple_list!(edges_observer, time_observer, bt_observer),
                    &mut fuzzer,
                    &mut state,
                    &mut mgr,
                )?,
                tuple_list!(cmplog_observer),
            );

            if is_repro {
                println!("inputs left: {}/{}", state.corpus().count(), total_len);
                if let Some(first_corpus_id) = state.corpus().first() {
                    let next_testcase = state.corpus_mut().remove(first_corpus_id).expect("failed to remove from corpus");
                    fuzzer.execute_input(&mut state, &mut executor, &mut mgr, &(next_testcase.input().clone()).unwrap()).unwrap();
                }
                return Err(libafl::Error::shutting_down());
            } else {
                {
                    let mut_visitor = &mut visitor.borrow_mut();
                    let mut generator = AutarkieGenerator::new(mut_visitor);
                    let _ = state.generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, INITIAL_GENERATED_INPUTS);
                }
                fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
            }
        
        Ok(())
    };

    let launcher_builder = Launcher::builder()
    .shmem_provider(shmem_provider)
    .configuration(EventConfig::from_name("default"))
    .monitor(monitor)
    .run_client(&mut secondary_run_client)    
    .cores(&cores)
    .broker_port(broker_port);

    let mut launcher = if is_repro {
        launcher_builder.build()
    } else {
        launcher_builder.stdout_file(Some("/dev/null")).build()
    };

    match launcher.launch()
        {
            Ok(()) => (),
            Err(Error::ShuttingDown) => println!("Fuzzing stopped. Good bye."),
            Err(err) => panic!("Failed to run launcher: {err:?}"),
        }

}