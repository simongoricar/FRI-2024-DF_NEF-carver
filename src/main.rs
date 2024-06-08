use std::{
    fs::{self, File, OpenOptions},
    io::{
        prelude::{Read, Write},
        BufReader,
        BufWriter,
        ErrorKind,
    },
    path::PathBuf,
};

use clap::Parser;
use humansize::{format_size, BINARY};
use miette::{miette, Context, IntoDiagnostic, Result};
use ringbuf::{
    storage::Heap,
    traits::{Consumer, RingBuffer},
    LocalRb,
};

#[derive(Parser, Debug)]
struct CliArgs {
    #[arg(short = 'i', long = "input-file-path")]
    input_file_path: PathBuf,

    #[arg(short = 'o', long = "output-file-path")]
    output_directory_path: PathBuf,
}

const MIN_NUM_BYTES_OF_SUSPECTED_IMAGE_TO_EXTRACT: usize = 1024 * 64;

const MAX_NUM_BYTES_OF_SUSPECTED_IMAGE_TO_EXTRACT: usize = 1024 * 1024 * 50;

/// Source: <http://lclevy.free.fr/nef/>
const NEF_MAGIC_BYTES: [u8; 8] = [
    0x4Du8, 0x4Du8, // "MM", which is a TIFF header
    0x00u8, 0x2Au8, // TIFF magic value
    0x00u8, 0x00u8, 0x00u8, 0x08u8, // TIFF offset
];


fn get_full_8byte_ring_buffer(ring_buffer: &LocalRb<Heap<u8>>) -> Option<[u8; 8]> {
    let (first_chunk, second_chunk) = ring_buffer.as_slices();
    if (first_chunk.len() + second_chunk.len()) != NEF_MAGIC_BYTES.len() {
        return None;
    }


    let mut full_chunk: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];

    let mut current_index = 0;

    for byte in first_chunk {
        if current_index > 7 {
            panic!("BUG: ring buffer was larger than 8 bytes");
        }

        full_chunk[current_index] = *byte;

        current_index += 1;
    }

    for byte in second_chunk {
        if current_index > 7 {
            panic!("BUG: ring buffer was larger than 8 bytes");
        }

        full_chunk[current_index] = *byte;

        current_index += 1;
    }


    Some(full_chunk)
}


#[inline]
fn is_suspected_nef_header(eight_byte_buffer: &[u8; 8]) -> bool {
    eight_byte_buffer == &NEF_MAGIC_BYTES
}


fn extract_suspected_nef_files(
    stream: &mut BufReader<File>,
    output_directory_path: PathBuf,
) -> Result<()> {
    let mut current_byte_offset_in_file: usize = 0;

    let mut ring_buffer = LocalRb::<Heap<u8>>::new(NEF_MAGIC_BYTES.len());
    let mut single_byte = [0u8];


    struct ExtractingFile {
        initial_byte_offset: usize,
        file: BufWriter<File>,
    }

    let mut currently_extracting_file: Option<ExtractingFile> = None;

    loop {
        let read_result = stream.read_exact(&mut single_byte);
        if let Err(read_error) = read_result {
            if read_error.kind() == ErrorKind::UnexpectedEof {
                return Ok(());
            } else {
                return Err(read_error).into_diagnostic();
            }
        }

        current_byte_offset_in_file += 1;
        ring_buffer.push_overwrite(single_byte[0]);

        let full_ring_buffer = get_full_8byte_ring_buffer(&ring_buffer);
        let Some(full_ring_buffer) = full_ring_buffer else {
            continue;
        };

        let is_suspected_nef = is_suspected_nef_header(&full_ring_buffer);


        if let Some(extracting_file) = currently_extracting_file.as_mut() {
            let bytes_so_far = current_byte_offset_in_file - extracting_file.initial_byte_offset;


            if is_suspected_nef && (bytes_so_far > MIN_NUM_BYTES_OF_SUSPECTED_IMAGE_TO_EXTRACT) {
                // The next file likely begins here, so we should finish the current one.
                println!(" -> next NEF is starting, closing extraction");

                extracting_file
                    .file
                    .flush()
                    .into_diagnostic()
                    .wrap_err("Failed to close extracting file.")?;

                currently_extracting_file = None;
            } else {
                extracting_file
                    .file
                    .write_all(&single_byte)
                    .into_diagnostic()
                    .wrap_err("Failed to write continuation byte extracting file.")?;


                if bytes_so_far > MAX_NUM_BYTES_OF_SUSPECTED_IMAGE_TO_EXTRACT {
                    println!(
                        " -> size {} exceeded, closing extraction",
                        format_size(MAX_NUM_BYTES_OF_SUSPECTED_IMAGE_TO_EXTRACT, BINARY)
                    );

                    extracting_file
                        .file
                        .flush()
                        .into_diagnostic()
                        .wrap_err("Failed to close extracting file.")?;

                    currently_extracting_file = None;
                }

                continue;
            }
        }

        if !is_suspected_nef {
            continue;
        }


        assert!(currently_extracting_file.is_none());


        println!(
            "Found potential NEF file at offset {} (~ {}).",
            current_byte_offset_in_file,
            format_size(current_byte_offset_in_file, BINARY)
        );



        let extracted_file_name = format!("extracted.{:#08x}.nef", current_byte_offset_in_file);
        let extracted_file_path = output_directory_path.join(&extracted_file_name);

        if extracted_file_path.exists() {
            return Err(miette!(
                "Invalid output directory: name collision for \"{}\".",
                extracted_file_name
            ));
        }


        let mut buffered_writer = {
            let file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&extracted_file_path)
                .into_diagnostic()
                .wrap_err("Failed to open file for extraction.")?;

            BufWriter::new(file)
        };


        buffered_writer
            .write_all(&full_ring_buffer)
            .into_diagnostic()
            .wrap_err("Failed to write initial chunk to file.")?;

        currently_extracting_file = Some(ExtractingFile {
            initial_byte_offset: current_byte_offset_in_file - 8,
            file: buffered_writer,
        });
    }
}

fn main() -> Result<()> {
    let cli_args = CliArgs::parse();

    if !cli_args.output_directory_path.exists() {
        fs::create_dir_all(&cli_args.output_directory_path)
            .into_diagnostic()
            .wrap_err("Failed to create missing output directory")?;
    } else if cli_args.output_directory_path.exists() && !cli_args.output_directory_path.is_dir() {
        return Err(miette!("Invalid output directory path: not a directory."));
    }

    let mut buffered_file = {
        let file = OpenOptions::new()
            .read(true)
            .open(cli_args.input_file_path)
            .into_diagnostic()
            .wrap_err("Failed to open input file.")?;

        BufReader::with_capacity(8192 * 16, file)
    };

    extract_suspected_nef_files(&mut buffered_file, cli_args.output_directory_path)
        .wrap_err("Failed to extract suspected NEF files.")?;

    drop(buffered_file.into_inner());
    Ok(())
}
