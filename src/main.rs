use clap::{App, Arg};
use goblin::pe::export::ExportAddressTableEntry::{ExportRVA, ForwarderRVA};
use goblin::pe::import::SyntheticImportLookupTableEntry::{HintNameTableRVA, OrdinalNumber};
use rusqlite::{Connection, ToSql};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::prelude::*;
use std::path::PathBuf;

fn visit_dirs_and_files(start: &PathBuf, cb: &Fn(&PathBuf)) {
    if start.is_dir() {
        if let Ok(entries) = fs::read_dir(start) {
            for entry in entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if path.is_dir() {
                        visit_dirs_and_files(&path, cb);
                    } else {
                        cb(&path);
                    }
                }
            }
        }
    } else if start.is_file() {
        cb(start);
    }
}

fn main() {
    let matches = App::new("dynamic-linking-statistics")
        .arg(
            Arg::with_name("sqlite")
                .short("s")
                .long("sqlite")
                .help("SQLite database path")
                .takes_value(true)
                .default_value("database.sqlite")
                .number_of_values(1),
        )
        .arg(
            Arg::with_name("files")
                .short("f")
                .long("files")
                .help("Path to file or folder to recursively search for executables")
                .takes_value(true)
                .number_of_values(1),
        )
        .arg(
            Arg::with_name("library_path")
                .short("l")
                .long("library-path")
                .help("Directories from which libraries can be looked up for necessary information")
                .takes_value(true)
                .multiple(true),
        )
        .arg(
            Arg::with_name("max_offset")
                .short("m")
                .long("max-offset")
                .help("Maximum relative offset to make statistics of")
                .takes_value(true)
                .number_of_values(1)
                .default_value("3"),
        )
        .subcommand(clap::SubCommand::with_name("generate")
                .arg(
                    Arg::with_name("mangled_symbols")
                        .number_of_values(1)
                        .takes_value(true)
                        .required(true)
                        .short("z")
                        .long("mangled-symbols")
                        .help("File that contains a list of mangled library symbols (export with MSVC dumpbin or others)"),
                )
                .arg(
                    Arg::with_name("library_list")
                        .takes_value(true)
                        .multiple(true)
                        .short("h")
                        .long("library-list")
                        .help("List of library names to restrict to")
                )
                .arg(
                    Arg::with_name("file_format")
                        .takes_value(true)
                        .short("p")
                        .long("file-format")
                        .help("File format to restrict to")
                )
                .arg(Arg::with_name("amount")
                        .takes_value(true)
                        .default_value("10")
                        .short("a")
                        .long("amount")
                        .help("Amount of mangled symbols to generate")
                )
        ).get_matches();

    let sqlite_path = matches.value_of("sqlite").unwrap().to_owned();
    let conn = Connection::open(sqlite_path).unwrap();

    conn.execute_batch(
        "
        PRAGMA journal_mode=MEMORY;
        PRAGMA synchronous=OFF;
        BEGIN;
            CREATE TABLE IF NOT EXISTS
                order_stats (
                    file_format TEXT,
                    library TEXT,
                    symbol TEXT,
                    relative_position INTEGER,
                    symbol_at_position TEXT,
                    count INTEGER DEFAULT 1 NOT NULL,
                    PRIMARY KEY (file_format, library, symbol, relative_position, symbol_at_position),
                    PRIMARY KEY (symbol, symbol_at_position, relative_position, library),
                    PRIMARY KEY (symbol, library)
                );
            CREATE TABLE IF NOT EXISTS
                processed_objects (
                    sha256 TEXT UNIQUE PRIMARY KEY
                );
        COMMIT;
    ",
    )
    .unwrap();

    if let ("generate", Some(g_matches)) = matches.subcommand() {
        use lazy_static::lazy_static;
        use regex::Regex;

        lazy_static! {
            static ref MANGLED_RE: Regex = Regex::new(
                r"(?m)^(?P<prefix>_|@)(?P<name>\w+?)(?P<suffix>@\d+)?$").unwrap();
        }

        let mangled_path = g_matches.value_of("mangled_symbols").unwrap().to_owned();
        let library_list: Vec<String> = match g_matches.is_present("library_list") {
            true => g_matches
                .values_of("library_list")
                .unwrap()
                .map(|x| x.to_string())
                .collect(),
            false => Vec::new(),
        };

        let query = format!("{} COLLATE NOCASE", "OR library = ? ".repeat(library_list.len()));
        let query = query.replacen("OR", "AND", 1);

        let mut mangled_file = String::new();

        fs::File::open(mangled_path).unwrap().read_to_string(&mut mangled_file).unwrap();

        let captures = MANGLED_RE.captures_iter(&mangled_file);

        use rand::prelude::*;
        use rand::seq::IteratorRandom;

        let mut rng = thread_rng();

        let captures_vec: Vec<(String, String)> = captures.map(|cap| (cap["name"].to_string(), cap[0].to_string())).collect();

        let start = captures_vec.iter().filter_map(|(name, full)| {
                            let mut args = vec![name.to_string()].to_vec();
                            args.append(&mut library_list.clone());

                            let q = conn.query_row(
                                &format!("SELECT rowid, library, symbol FROM order_stats WHERE symbol = ? {}", query),
                                args,
                                move |row| Ok((row.get::<_, i64>(0).unwrap(), row.get::<_, String>(1).unwrap(), row.get::<_, String>(2).unwrap(), full.to_string().to_owned()))
                            );

                            if q.is_ok() {
                                Some(q.unwrap())
                            } else {
                                None
                            }
                        })
                .choose(&mut rng).unwrap();

        let (_rowid, _library, symbol, mangled) = start;

        let mut result: Vec<String> = Vec::new();

        result.push(mangled.to_string());


        let mut last_added = symbol;


        println!("{}", last_added);

        for _ in 0..g_matches.value_of("amount").unwrap().parse().unwrap() {

            use rand::seq::SliceRandom;

        let weights: Vec<(String, String, String, i64, String)> = captures_vec.iter().filter_map(|(name, full)| {
                            let mut args = vec![last_added.to_string(), name.to_string(), "1".to_string()].to_vec();
                            args.append(&mut library_list.clone());

                            for x in result.iter() {
                                if x == full {
                                    return None;
                                }
                            }

                            let q = conn.query_row(
                                &format!("SELECT library, symbol, symbol_at_position, count FROM order_stats WHERE symbol = ? AND symbol_at_position = ? AND relative_position = ? {}", query),
                                args,
                                move |row| Ok((row.get::<_, String>(0).unwrap(), row.get::<_, String>(1).unwrap(), row.get::<_, String>(2).unwrap(), row.get::<_, i64>(3).unwrap(), full.to_string().to_owned()))
                            );

                            if q.is_ok() {
                                Some(q.unwrap())
                            } else {
                                None
                            }
                        }).collect();

            let filtered: Vec<_> = weights.iter().collect();
             
            let (_, _, symbol_at_position, _, next) = filtered.choose_weighted(&mut rng, |(_library, _symbol, _symbol_at_position, count, _mangled)| *count).unwrap();


        result.push(next.to_string());
        last_added = symbol_at_position.to_string();

        println!("{}", last_added);

        }

        println!("\n\n");
        for x in result.iter() {
            println!("{}", x);
        }

        return;
    }

    let files_path = match matches.is_present("files") {
        true => std::path::PathBuf::from(matches.value_of("files").unwrap()),
        false => std::env::current_dir().unwrap(),
    };

    let max_offset: usize = matches.value_of("max_offset").unwrap().parse().unwrap();
    let max_offset: isize = max_offset as isize;

    let library_paths: Vec<PathBuf> = match matches.is_present("library_path") {
        true => matches
            .values_of("library_path")
            .unwrap()
            .map(|x| std::path::PathBuf::from(x.to_string()))
            .collect(),
        false => Vec::new(),
    };

    let analyze_file = move |path: &PathBuf| {
        println!(
            "{} processing..",
            path.to_str().unwrap_or("<could not decode path>")
        );

        if let Ok(file) = fs::File::open(path) {
            let mut buffer = Vec::new();

            if file
                .take(41943040 /* 40 MB */)
                .read_to_end(&mut buffer)
                .is_ok()
            {
                let mut hasher = Sha256::new();

                hasher.input(&buffer);

                let hex_hash = hex::encode(hasher.result());

                if let Err(_) = conn.query_row(
                    "SELECT rowid FROM processed_objects WHERE sha256 = ?",
                    &[&hex_hash as &ToSql],
                    |row| row.get::<_, i64>(0),
                ) {
                    if let Ok(pe) = goblin::pe::PE::parse(&buffer) {
                        let mut imports: HashMap<String, Vec<String>> = HashMap::new();

                        if let Some(x) = pe.import_data {
                            for import in x.import_data {
                                let mut names = Vec::new();
                                let mut break_early = false;

                                if let Some(ilt) = import.import_lookup_table {
                                    for entry in ilt {
                                        match entry {
                                            HintNameTableRVA((_, hint_entry)) => {
                                                names.push(hint_entry.name.to_string())
                                            }
                                            OrdinalNumber(ordinal) => {
                                                let mut found = false;

                                                for path in library_paths.iter() {
                                                    if path.is_dir() {
                                                        if let Ok(entries) = fs::read_dir(path) {
                                                            for entry in entries {
                                                                if let Ok(entry) = entry {
                                                                    let path = entry.path();
                                                                    if path.is_file() {
                                                                        if entry
                                                                            .file_name()
                                                                            .to_str()
                                                                            .unwrap()
                                                                            .to_lowercase()
                                                                            == import
                                                                                .name
                                                                                .to_lowercase()
                                                                        {
                                                                            if let Ok(file) =
                                                                                fs::File::open(path)
                                                                            {
                                                                                let mut buffer =
                                                                                    Vec::new();
                                                                                if file
                                                                                .take(41943040 /* 40 MB */)
                                                                                    .read_to_end(
                                                                                        &mut buffer,
                                                                                    )
                                                                                    .is_ok()
                                                                                {
                                                                                    if let Ok(pe) =
                                                                                            goblin::pe::PE::parse(&buffer)
                                                                                        {
                                                                                           
                                                                                            if let Some(
                                                                                                export_data,
                                                                                                ) = pe.export_data
                                                                                            {
                                                                                                if let Some(export_rva) = export_data.export_address_table.get((ordinal as u32 - export_data.export_directory_table.ordinal_base) as usize) {
                                                                                                    let export_rva = match export_rva {
                                                                                                        ExportRVA(x) => x,
                                                                                                        ForwarderRVA(x) => x,
                                                                                                    };

                                                                                                    if let Some(export) = pe.exports.iter().filter(|e| e.rva == *export_rva as usize).next() {
                                                                                                        if let Some(name) = export.name {
                                                                                                            found = true;
                                                                                                            names.push(name.to_string());
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                            
                                                                                        }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                if found == false {
                                                    break_early = true;
                                                    break;
                                                }
                                            }
                                        };
                                    }
                                }
                                if break_early == false {
                                    imports.insert(import.name.to_string(), names);
                                }
                            }
                        }

                        let mut statistics: HashMap<(String, String, isize), String> =
                            HashMap::new();

                        for kv_imports in imports.iter() {
                            let (library, symbols) = kv_imports;

                            for (index, symbol) in symbols.iter().enumerate() {
                                for (r_index, r_symbol) in symbols.iter().enumerate() {
                                    if r_index == index {
                                        continue;
                                    }

                                    let relative_index = (r_index as isize) - (index as isize);

                                    if relative_index > 0 && relative_index > max_offset {
                                        continue;
                                    } else if relative_index < 0 && relative_index < -max_offset {
                                        continue;
                                    }

                                    statistics.insert(
                                        (library.to_string(), symbol.to_string(), relative_index),
                                        r_symbol.to_string(),
                                    );
                                }
                            }
                        }

                        println!("adding/updating {} records", statistics.len());

                        let now = std::time::Instant::now();

                        let mut stmt = conn
                            .prepare(
                                "INSERT INTO
                                                    order_stats (
                                                        file_format,
                                                        library,
                                                        symbol,
                                                        relative_position,
                                                        symbol_at_position
                                                    )
                                                VALUES
                                                    (?, ?, ?, ?, ?)",
                            )
                            .unwrap();

                        for kv_statistics in statistics.iter() {
                            let ((lib, sym, index), r_sym) = kv_statistics;

                            if let Ok(rowid) = conn.query_row(
                                "                       SELECT
                                                                rowid
                                                            FROM
                                                                order_stats
                                                            WHERE
                                                                file_format = ?
                                                            AND
                                                                library = ?
                                                            AND
                                                                symbol = ?
                                                            AND
                                                                relative_position = ?
                                                            AND
                                                                symbol_at_position = ?",
                                &[&"pe" as &ToSql, lib, sym, index, r_sym],
                                |row| row.get::<_, i64>(0),
                            ) {
                                conn.execute(
                                    "UPDATE
                                            order_stats
                                        SET
                                            count = count + 1
                                        WHERE
                                            rowid = ?",
                                    &[&rowid as &ToSql],
                                )
                                .unwrap();
                            } else {
                                stmt.execute(&[&"pe" as &ToSql, lib, sym, index, r_sym])
                                    .unwrap();
                            }
                        }

                        println!("completed in {} ms", now.elapsed().as_millis());
                    }
                }

                conn.execute(
                    "INSERT INTO processed_objects (sha256) VALUES (?)",
                    &[&hex_hash as &ToSql],
                )
                .is_err();
            }
        }
    };

    visit_dirs_and_files(&files_path, &analyze_file);
}
