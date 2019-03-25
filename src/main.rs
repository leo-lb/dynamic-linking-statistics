use clap::{App, Arg};
use goblin::pe::export::ExportAddressTableEntry::{ExportRVA, ForwarderRVA};
use goblin::pe::import::SyntheticImportLookupTableEntry::{HintNameTableRVA, OrdinalNumber};
use goblin::Object;
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
        .get_matches();

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
                    PRIMARY KEY (file_format, library, symbol, relative_position, symbol_at_position)
                );
            CREATE TABLE IF NOT EXISTS
                processed_objects (
                    sha256 TEXT UNIQUE PRIMARY KEY
                );
        COMMIT;
    ",
    )
    .unwrap();

    let files_path = match matches.is_present("files") {
        true => std::path::PathBuf::from(matches.value_of("files").unwrap()),
        false => std::env::current_dir().unwrap(),
    };

    let max_offset: usize = matches.value_of("max_offset").unwrap().parse().unwrap();

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

        if let Ok(mut file) = fs::File::open(path) {
            let mut buffer = Vec::new();
            if file.read_to_end(&mut buffer).is_ok() {
                let mut hasher = Sha256::new();

                hasher.input(&buffer);

                let hex_hash = hex::encode(hasher.result());

                if let Err(_) = conn.query_row(
                    "SELECT rowid FROM processed_objects WHERE sha256 = ?",
                    &[&hex_hash as &ToSql],
                    |row| row.get::<_, i64>(0),
                ) {
                    if let Ok(parsed) = Object::parse(&buffer) {
                        match parsed {
                            Object::Elf(_elf) => {
                                eprintln!(
                                    "{} elf: {}",
                                    path.to_str().unwrap_or("<could not decode path>"),
                                    "unimplemented"
                                );
                            }
                            Object::PE(pe) => {
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
                                                                if let Ok(entries) =
                                                                    fs::read_dir(path)
                                                                {
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
                                                                                if let Ok(
                                                                                    mut file,
                                                                                ) =
                                                                                    fs::File::open(
                                                                                        path,
                                                                                    )
                                                                                {
                                                                                    let mut buffer =
                                                                                        Vec::new();
                                                                                    if file.read_to_end(&mut buffer).is_ok() {
                                                                                        if let Ok(parsed) =
                                                                                            Object::parse(&buffer)
                                                                                        {
                                                                                            match parsed {
                                                                                                Object::PE(pe) => {
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
                                                                                                _ => {}
                                                                                            };
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

                                            statistics.insert(
                                                (
                                                    library.to_string(),
                                                    symbol.to_string(),
                                                    ((r_index as isize) - (index as isize)),
                                                ),
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

                                for kv_statistics in
                                    statistics.iter().filter(|((_lib, _sym, index), _r_sym)| {
                                        max_offset as isize >= *index
                                            && -*index >= -(max_offset as isize)
                                    })
                                {
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
                            Object::Mach(_mach) => {
                                eprintln!(
                                    "{} mach: {}",
                                    path.to_str().unwrap_or("<could not decode path>"),
                                    "unimplemented"
                                );
                            }
                            Object::Archive(_archive) => {
                                eprintln!(
                                    "{} archive: {}",
                                    path.to_str().unwrap_or("<could not decode path>"),
                                    "excluded from study"
                                );
                            }
                            Object::Unknown(_magic) => eprintln!(
                                "{} unknown magic",
                                path.to_str().unwrap_or("<could not decode path>")
                            ),
                        }
                    }

                    conn.execute(
                        "INSERT INTO processed_objects (sha256) VALUES (?)",
                        &[&hex_hash as &ToSql],
                    )
                    .unwrap();
                }
            }
        }
    };

    visit_dirs_and_files(&files_path, &analyze_file);
}
