mod helpers;
mod modules;

use std::fs;
use rustop::opts;
use clap::{App, Arg};
use klask::Settings;
use flexi_logger::*;
use arrayvec::ArrayVec;
use csv::ReaderBuilder;
use std::env;
use std::path::Path;

use yara::*;

use crate::helpers::helpers::{get_hostname, get_os_type, evaluate_env};
use crate::modules::process_check::scan_processes;
use crate::modules::filesystem_scan::scan_path;

// Specific TODOs
// - skipping non-local file systems like network mounts or cloudfs drives

// General TODOs
// - better error handling
// - putting all modules in an array and looping over that list instead of a fixed sequence
// - restructuring project to multiple files

const VERSION: &str = "2.0.1-alpha";

// const SIGNATURE_SOURCE: &str = std::env::current_exe()
const MODULES: &'static [&'static str] = &["FileScan", "ProcessCheck"];

#[derive(Debug)]
pub struct GenMatch {
    message: String,
    score: i16,
}

pub struct YaraMatch {
    rulename: String,
    score: i16,
}

pub struct ScanConfig {
    max_file_size: usize,
    show_access_errors: bool,
    scan_all_types: bool,
}

#[derive(Debug)]
pub struct ExtVars {
    filename: String,
    filepath: String,
    filetype: String,
    extension: String,
    owner: String,
}

#[derive(Debug)]
pub struct HashIOC {
    hash_type: HashType,
    hash_value: String,
    description: String,
    score: i16,
}

#[derive(Debug)]
pub enum HashType {
    Md5,
    Sha1,
    Sha256,
    Unknown
}

#[derive(Debug)]
pub struct FilenameIOC {
    pattern: String, 
    ioc_type: FilenameIOCType,
    description: String, 
    score: i16,
}

#[derive(Debug)]
pub enum FilenameIOCType {
    String,
    Regex
}

// TODO: under construction - the data structure to hold the IOCs is still limited to 100.000 elements. 
//       I have to find a data structure that allows to store an unknown number of entries.
// Initialize the IOCs
fn initialize_hash_iocs(path:&str ) -> Vec<HashIOC> {
    // Compose the location of the hash IOC file
    let hash_ioc_file = Path::new(path).join(Path::new("iocs")).join(Path::new("hash-iocs.txt")).into_os_string().into_string().expect("failed to load hash-iocs.txt error").to_string();

    log::debug!("{}",hash_ioc_file);
    // let hash_ioc_file = format!("{}/iocs/hash-iocs.txt", SIGNATURE_SOURCE);
    // Read the hash IOC file
    let hash_iocs_string = fs::read_to_string(hash_ioc_file).expect("Unable to read hash IOC file (use --debug for more information)");
    // Configure the CSV reader
    let mut reader = ReaderBuilder::new()
        .delimiter(b';')
        .flexible(true)
        .from_reader(hash_iocs_string.as_bytes());
    // Vector that holds the hashes
    let mut hash_iocs:Vec<HashIOC> = Vec::new();
    // Read the lines from the CSV file
    for result in reader.records() {
        let record_result = result;
        let record = match record_result {
            Ok(r) => r,
            Err(e) => { log::debug!("Cannot read line in hash IOCs file (which can be okay) ERROR: {:?}", e); continue;}
        };
        // If more than two elements have been found
        if record.len() > 1 {
            // if it's not a comment line
            if !record[0].starts_with("#") {
                // determining hash type
                let hash_type: HashType = get_hash_type(&record[0]);
                log::trace!("Read hash IOC from from HASH: {} DESC: {} TYPE: {:?}", &record[0], &record[1], hash_type);
                hash_iocs.push(
                    HashIOC { 
                        hash_type: hash_type,
                        hash_value: record[0].to_ascii_lowercase(), 
                        description: record[1].to_string(), 
                        score: 100,  // TODO 
                    });
            }
        }
    }
    log::info!("Successfully initialized {} hash values", hash_iocs.len());
    return hash_iocs;
}

// Get the hash type
fn get_hash_type(hash_value: &str) -> HashType {
    let hash_value_length = hash_value.len();
    match hash_value_length {
        32 => HashType::Md5,
        40 => HashType::Sha1,
        64 => HashType::Sha256,
        _ => HashType::Unknown,
    }
} 

// Initialize filename IOCs / patterns
fn initialize_filename_iocs(path:&str) -> Vec<FilenameIOC> {
    // Compose the location of the hash IOC file
    let filename_ioc_file = Path::new(path).join(Path::new("iocs")).join(Path::new("filename-iocs.txt")).into_os_string().into_string().expect("failed to load filename-iocs.txt").to_string();
    log::debug!("{}",filename_ioc_file);
    // let filename_ioc_file = format!("{}/iocs/filename-iocs.txt", SIGNATURE_SOURCE);
    // Read the hash IOC file
    let filename_iocs_string = fs::read_to_string(filename_ioc_file).expect("Unable to read filename IOC file (use --debug for more information)");
    // Vector that holds the hashes
    let mut filename_iocs:Vec<FilenameIOC> = Vec::new();
    // Configure the CSV reader
    let mut reader = ReaderBuilder::new()
        .delimiter(b';')
        .flexible(true)
        .from_reader(filename_iocs_string.as_bytes());
    
    // Preset description 
    let mut description = "N/A".to_string();
    // Read the lines from the CSV file
    for result in reader.records() {
        let record_result = result;
        let record = match record_result {
            Ok(r) => r,
            Err(e) => { log::debug!("Cannot read line in hash IOCs file (which can be okay) ERROR: {:?}", e); continue;}
        };
        // If line couldn't be split up (no separator)
        if record.len() == 1 {
            // If line starts with # ... this is a description
            if record[0].starts_with("# ") {
                description = record[0].strip_prefix("# ").unwrap().to_string();
            }
            else if record[0].starts_with("#") {
                description = record[0].strip_prefix("#").unwrap().to_string();
            }
        }
        // If more than two elements have been found
        if record.len() > 1 {
            // if it's not a comment line
            if !record[0].starts_with("#") {
                // determining hash type
                let filename_ioc_type = get_filename_ioc_type(&record[0]);
                log::trace!("Read filename IOC from from PATTERN: {} TYPE: {:?} SCORE: {}", &record[0], filename_ioc_type, &record[1]);
                filename_iocs.push(
                    FilenameIOC { 
                        pattern: record[0].to_ascii_lowercase(),
                        ioc_type: filename_ioc_type,
                        description: description.clone(), 
                        score: record[1].parse::<i16>().unwrap(),  // TODO 
                    });
            }
        }
    }
    log::info!("Successfully initialized {} filename IOC values", filename_iocs.len());

    // Return file name IOCs
    return filename_iocs;
}

fn get_filename_ioc_type(filename_ioc_value: &str) -> FilenameIOCType {
    // TODO ... detect filename IOC type
    // currently every filename gets detected and initialized as regex (which consumes a lot of memory)
    return FilenameIOCType::Regex;
} 

// Initialize the rule files
fn initialize_yara_rules(path:&str) -> Rules {
    // Composed YARA rule set 
    // we're concatenating all rules from all rule files to a single string and 
    // compile them all together into a single big rule set for performance purposes
    let mut all_rules = String::new();
    let mut count = 0u16;
    // Reading the signature folder
    let yara_sigs_folder = Path::new(path).join(Path::new("yara")).into_os_string().into_string().expect("failed to load yara folder").to_string();
    log::debug!("{}",yara_sigs_folder);
    
    // let yara_sigs_folder = format!("{}/yara", SIGNATURE_SOURCE);
    let files = fs::read_dir(yara_sigs_folder).unwrap();
    // Filter 
    let filtered_files = files
        .filter_map(Result::ok)
        .filter(|d| if let Some(e) = d.path().extension() { e == "yar" } else { false })
        .into_iter();
    // Test compile each rule
    for file in filtered_files {
        log::debug!("Reading YARA rule file {} ...", file.path().to_str().unwrap());
        // Read the rule file
        let rules_string = fs::read_to_string(file.path()).expect("Unable to read YARA rule file (use --debug for more information)");
        let compiled_file_result = compile_yara_rules(&rules_string);
        match compiled_file_result {
            Ok(_) => { 
                log::debug!("Successfully compiled rule file {:?} - adding it to the big set", file.path().to_str().unwrap());
                // adding content of that file to the whole rules string
                all_rules += &rules_string;
                count += 1;
            },
            Err(e) => {
                log::error!("Cannot compile rule file {:?}. Ignoring file. ERROR: {:?}", file.path().to_str().unwrap(), e)                
            }
        };
    }
    // Compile the full set and return the compiled rules
    let compiled_all_rules = compile_yara_rules(&all_rules)
        .expect("Error parsing the composed rule set");
    log::info!("Successfully compiled {} rule files into a big set", count);
    return compiled_all_rules;
}

// Compile a rule set string and check for errors
fn compile_yara_rules(rules_string: &str) -> Result<Rules, Error> {
    let mut compiler = Compiler::new().unwrap();
    compiler.define_variable("filename", "")?;
    compiler.define_variable("filepath", "")?;
    compiler.define_variable("extension", "")?;
    compiler.define_variable("filetype", "")?;
    compiler.define_variable("owner", "")?;
    // Parse the rules
    let compiler_result = compiler
        .add_rules_str(rules_string);
    // Handle parse errors
    let compiler = match compiler_result {
        Ok(c) => c,
        Err(e) => return Err(Error::from(e)),
    };
    // Compile the rules
    let compiled_rules_result = compiler.compile_rules();
    // Handle compile errors
    let compiled_rules = match compiled_rules_result {
        Ok(r) => r,
        Err(e) => return Err(Error::from(e)),
    };
    // Return the compiled rule set
    return Ok(compiled_rules);
}

// Log file format for files
fn log_file_format(
    write: &mut dyn std::io::Write,
    now: &mut flexi_logger::DeferredNow,
    record: &log::Record,
 ) -> std::io::Result<()> {
    write!(
        write,
        "[{}] {} {}",
        now.format("%Y-%m-%dT%H:%M:%SZ"),
        record.level(),
        &record.args()
    )
}

// Log file format for command line
fn log_cmdline_format(
    w: &mut dyn std::io::Write,
    _now: &mut DeferredNow,
    record: &Record,
) -> Result<(), std::io::Error> {
    let level = record.level();
    write!(
        w,
        "[{}] {}",
        style(level).paint(level.to_string()),
        record.args().to_string()
    )
}


fn main() {

    let matches = App::new("LOKI YARA and IOC Scanner")
        .arg(
            Arg::with_name("max_file_size")
                .short('m')
                .long("max-file-size")
                .takes_value(true)
                .value_name("SIZE")
                .help("Maximum file size to scan")
                .default_value("10000000")
        )
        .arg(
            Arg::with_name("folder")
                .help("Folder to scan")
                .index(1)
                .takes_value(true)
                .required(true),
    );



    klask::run_app(matches, Settings::default(), |m| {
        // println!("{}", m.value_of("debug"))
        let max_file_size = m.value_of("max_file_size").unwrap().parse().unwrap();
        let folder = m.value_of("folder").map(String::from).unwrap();
        


        let scan_config = ScanConfig {
            max_file_size: max_file_size,
            show_access_errors: true,
            scan_all_types: true,
        };
        let mut log_level: String = "info".to_string(); let mut std_out = Duplicate::Info; // default
        let log_file_name = format!("loki_{}", get_hostname());
        Logger::try_with_str(log_level).unwrap()
            .log_to_file(
                FileSpec::default()
                    .basename(log_file_name)
            )
            .use_utc()
            .format(log_cmdline_format)
            .format_for_files(log_file_format)
            .duplicate_to_stdout(std_out)
            .append()
            .start()
            .unwrap();
        log::info!("LOKI scan started VERSION: {}", VERSION);
        evaluate_env();




        let mut active_modules: ArrayVec<String, 20> = ArrayVec::<String, 20>::new();
        for module in MODULES {
        //     if module.to_string() == "ProcessCheck" { continue; }
        //     if module.to_string() == "FileScan" { continue; }
            active_modules.insert(active_modules.len(), module.to_string());
        }
        log::info!("Active modules MODULES: {:?}", active_modules);

        let mut target_folder = folder;
        

        let path = std::env::current_exe().unwrap().parent().unwrap().join(Path::new("signatures")).into_os_string().into_string().expect("REASON").to_string();
        // Initialize IOCs 
        log::info!("Initialize hash IOCs ...");
        let hash_iocs = initialize_hash_iocs(&path);
        log::info!("Initialize filename IOCs ...");
        let filename_iocs = initialize_filename_iocs(&path);

        // Initialize the YARA rules
        log::info!("Initializing YARA rules ...");
        let compiled_rules = initialize_yara_rules(&path);

        // Process scan
        if active_modules.contains(&"ProcessCheck".to_owned()) {
            log::info!("Scanning running processes ... ");
            scan_processes(&compiled_rules, &scan_config);
        }

        // File system scan
        if active_modules.contains(&"FileScan".to_owned()) {
            log::info!("Scanning local file system ... ");
            scan_path(target_folder, &compiled_rules, &scan_config, &hash_iocs, &filename_iocs);
        }

        // Finished scan
        log::info!("LOKI scan finished");
    });

}
