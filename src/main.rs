use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::DirEntry;
use std::fs::File;
use std::fs::{self};
use std::io::prelude::*;
use std::io::SeekFrom;
use std::path::Path;
use std::time::Duration;

use rusb::{Context, Device, DeviceDescriptor, DeviceHandle, Direction, UsbContext};

static VID: u16 = 0x057e;
static PID: u16 = 0x3000;

fn main() {
    let mut root = "/";
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 {
        root = &args[1].trim_end_matches('/');
    }

    match Switch::new() {
        Ok(switch) => {
            let handler = GoldleafHandler::new(switch, String::from(root));
            handler.listen();
        }
        Err(msg) => {
            eprintln!("{}", msg);
        }
    }
}

#[derive(Debug)]
struct Endpoint {
    config: u8,
    iface: u8,
    setting: u8,
    address: u8,
}

pub struct Switch {
    handle: DeviceHandle<Context>,
    input: Endpoint,
    output: Endpoint,
}

impl Switch {
    pub fn new() -> Result<Self, String> {
        match Context::new() {
            Ok(mut context) => match find_device(&mut context) {
                Some((mut device, device_desc, handle)) => {
                    match find_endpoints(&mut device, &device_desc) {
                        (Some(input), Some(output)) => Ok(Self {
                            handle,
                            input,
                            output,
                        }),
                        _ => Err(String::from("could not find endpoints")),
                    }
                }
                None => {
                    return Err(format!("could not find device {:04x}:{:04x}", VID, PID));
                }
            },

            Err(e) => return Err(format!("could not initialize libusb: {}", e)),
        }
    }
}

fn find_device<T: UsbContext>(
    context: &mut T,
) -> Option<(Device<T>, DeviceDescriptor, DeviceHandle<T>)> {
    let devices = match context.devices() {
        Ok(d) => d,
        Err(_) => return None,
    };

    for device in devices.iter() {
        let device_desc = match device.device_descriptor() {
            Ok(d) => d,
            Err(_) => continue,
        };

        if device_desc.vendor_id() == VID && device_desc.product_id() == PID {
            match device.open() {
                Ok(handle) => return Some((device, device_desc, handle)),
                Err(_) => continue,
            }
        }
    }
    None
}

fn find_endpoints<T: UsbContext>(
    device: &mut Device<T>,
    device_desc: &DeviceDescriptor,
) -> (Option<Endpoint>, Option<Endpoint>) {
    for n in 0..device_desc.num_configurations() {
        let config_desc = match device.config_descriptor(n) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mut input: Option<Endpoint> = None;
        let mut output: Option<Endpoint> = None;
        for interface in config_desc.interfaces() {
            for interface_desc in interface.descriptors() {
                for endpoint_desc in interface_desc.endpoint_descriptors() {
                    if endpoint_desc.direction() == Direction::In {
                        input = Some(Endpoint {
                            config: config_desc.number(),
                            iface: interface_desc.interface_number(),
                            setting: interface_desc.setting_number(),
                            address: endpoint_desc.address(),
                        });
                    } else if endpoint_desc.direction() == Direction::Out {
                        output = Some(Endpoint {
                            config: config_desc.number(),
                            iface: interface_desc.interface_number(),
                            setting: interface_desc.setting_number(),
                            address: endpoint_desc.address(),
                        });
                    }
                }
            }
        }
        return (input, output);
    }
    (None, None)
}

struct Command {
    buf: [u8; 0x1000],
    ptr: usize,
}

impl Command {
    fn new() -> Self {
        Self {
            buf: [0; 0x1000],
            ptr: 8,
        }
    }

    fn from(buf: [u8; 0x1000]) -> Self {
        Self { buf, ptr: 0 }
    }

    fn error(&mut self) {
        self.write_to(&0xcb64u32.to_le_bytes(), 0)
    }

    fn read(&mut self, len: usize) -> &[u8] {
        let ret = &self.buf[self.ptr..self.ptr + len];
        self.ptr += len;
        ret
    }

    fn read_u32(&mut self) -> u32 {
        return u32::from_le_bytes(self.read(4).try_into().unwrap());
    }

    fn read_u64(&mut self) -> u64 {
        return u64::from_le_bytes(self.read(8).try_into().unwrap());
    }

    fn read_string(&mut self) -> String {
        let size = self.read_u32() as usize;
        let slice = self.read(size * 2);
        let mut temp: Vec<u16> = Vec::new();
        for i in (0..slice.len()).step_by(2) {
            temp.push(u16::from_le_bytes(slice[i..i + 2].try_into().unwrap()));
        }
        String::from_utf16(&temp).unwrap()
    }

    fn read_path(&mut self, root: &str) -> String {
        let path = self
            .read_string()
            .split(':')
            .nth(1)
            .unwrap()
            .trim_end_matches('/')
            .to_string();
        String::from(root) + &path
    }

    fn write_to(&mut self, bytes: &[u8], offset: usize) {
        self.buf[offset..(bytes.len() + offset)].clone_from_slice(&bytes);
    }

    fn write(&mut self, bytes: &[u8]) {
        self.write_to(bytes, self.ptr);
        self.ptr += bytes.len();
    }

    fn write_u8(&mut self, value: u8) {
        self.write(&[value]);
    }

    fn write_u16(&mut self, value: u16) {
        self.write(&(value).to_le_bytes());
    }

    fn write_u32(&mut self, value: u32) {
        self.write(&(value).to_le_bytes());
    }

    fn write_u64(&mut self, value: u64) {
        self.write(&(value).to_le_bytes());
    }

    fn write_string(&mut self, text: &str) {
        let s: Vec<u16> = text.encode_utf16().collect();
        self.write_u32(s.len() as u32);
        for i in s {
            self.write_u16(i);
        }
    }
}

pub struct GoldleafHandler {
    switch: Switch,
    root: String,
    cache: HashMap<String, (Vec<DirEntry>, Vec<DirEntry>)>,
    files: HashMap<String, File>,
}

impl GoldleafHandler {
    pub fn new(switch: Switch, root: String) -> Self {
        Self {
            switch,
            root,
            cache: HashMap::<String, (Vec<DirEntry>, Vec<DirEntry>)>::new(),
            files: HashMap::<String, File>::new(),
        }
    }

    fn read_dir<'a>(
        &'a mut self,
        path: &str,
    ) -> Result<&(Vec<DirEntry>, Vec<DirEntry>), std::io::Error> {
        if !self.cache.contains_key(path) {
            match fs::read_dir(String::from(path)) {
                Ok(values) => {
                    let mut dirs: Vec<DirEntry> = Vec::new();
                    let mut files: Vec<DirEntry> = Vec::new();
                    let values: Vec<DirEntry> = values.map(|r| r.unwrap()).collect();
                    for value in values {
                        if value.path().is_dir() {
                            dirs.push(value);
                        } else {
                            files.push(value);
                        }
                    }
                    self.cache.insert(String::from(path), (dirs, files));
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }
        return Ok(self.cache.get(path).unwrap());
    }

    fn stat(&self, mut cmd: Command, out: &mut Command) {
        let path = cmd.read_path(&self.root);
        let path = Path::new(&path);
        if path.is_file() {
            out.write_u32(1);
            out.write_u64(path.metadata().unwrap().len())
        } else if path.is_dir() {
            out.write_u32(2);
            out.write_u64(0);
        } else {
            out.error();
        }
    }

    pub fn open_file<'a>(&'a mut self, path: &str) -> Result<&File, std::io::Error> {
        if !self.files.contains_key(path) {
            match File::open(String::from(path)) {
                Ok(file) => {
                    self.files.insert(String::from(path), file);
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }
        return Ok(self.files.get(path).unwrap());
    }

    fn get_count(&mut self, mut cmd: Command, out: &mut Command, dir: bool) {
        let path = cmd.read_path(&self.root);
        match self.read_dir(&path) {
            Ok((dirs, files)) => {
                out.write_u32((if dir { dirs } else { files }).len() as u32);
            }
            Err(err) => {
                println!("error {}", err);
                out.error();
            }
        }
    }

    fn get_element(&mut self, mut cmd: Command, out: &mut Command, dir: bool) {
        let path = cmd.read_path(&self.root);
        let index = cmd.read_u32();
        match self.read_dir(&path) {
            Ok((dirs, files)) => {
                out.write_string(
                    &(if dir { dirs } else { files })
                        .get(index as usize)
                        .unwrap()
                        .file_name()
                        .into_string()
                        .unwrap(),
                );
            }
            Err(err) => {
                println!("error {}", err);
                out.error();
            }
        }
    }

    fn read_file(&mut self, cmd: &mut Command, out: &mut Command) {
        let path = cmd.read_path(&self.root);
        let offset = cmd.read_u64();
        let size = cmd.read_u64();
        match self.open_file(&path) {
            Ok(mut file) => match file.seek(SeekFrom::Start(offset)) {
                Ok(_) => {
                    out.write_u64(size);
                    let mut data = vec![0; size as usize];
                    file.read_exact(&mut data).expect("error read");
                    self.switch
                        .handle
                        .write_bulk(
                            self.switch.output.address,
                            &out.buf,
                            Duration::from_millis(100),
                        )
                        .expect("Unable to send data");
                    self.switch
                        .handle
                        .write_bulk(
                            self.switch.output.address,
                            &data,
                            Duration::from_millis(10000),
                        )
                        .expect("Unable to send file");
                }
                Err(err) => {
                    println!("Unable to seek file: {}", err);
                    out.error();
                }
            },
            Err(err) => {
                println!("Unable to open file: {}", err);
                out.error();
            }
        }
    }

    fn write_file(&mut self, cmd: &mut Command, out: &mut Command) {
        let path = cmd.read_path(&self.root);
        let size = cmd.read_u64();
        // FIXME
        let mut data = vec![0; size as usize];
        self.switch
            .handle
            .read_bulk(
                self.switch.input.address,
                &mut data,
                Duration::from_millis(10000),
            )
            .expect("Unable to receive data");
        match self.open_file(&path) {
            Ok(mut file) => {
                file.write_all(&data).expect("Unable to write data");
                self.cache.remove(&path[0..path.rfind('/').unwrap()]);
            }
            Err(err) => {
                println!("Unable to open file: {}", err);
                out.error();
            }
        }
    }

    fn create(&mut self, cmd: &mut Command, mut out: &mut Command) {
        let sort = cmd.read_u32();
        let path = cmd.read_path(&self.root);
        let fun = if sort == 1 {
            |path: String| -> std::io::Result<()> {
                match File::create(path) {
                    Ok(_) => Ok(()),
                    Err(err) => Err(err),
                }
            }
        } else {
            fs::create_dir
        };
        self.call_fun(&path, &mut out, fun);
    }

    fn delete(&mut self, cmd: &mut Command, mut out: &mut Command) {
        let sort = cmd.read_u32();
        let path = cmd.read_path(&self.root);
        self.call_fun(
            &path,
            &mut out,
            if sort == 1 {
                fs::remove_file
            } else {
                fs::remove_dir_all
            },
        )
    }

    fn rename(&mut self, cmd: &mut Command, mut out: &mut Command) {
        let sort = cmd.read_u32();
        let path = cmd.read_path(&self.root);
        let new = if sort == 1 {
            String::from(&path[0..path.rfind('/').unwrap() + 1]) + &cmd.read_string()
        } else {
            cmd.read_path(&self.root)
        };
        self.call_fun(&path, &mut out, |x: String| -> std::io::Result<()> {
            fs::rename(x, &new)
        })
    }

    fn call_fun<F>(&mut self, path: &str, out: &mut Command, f: F)
    where
        F: Fn(String) -> std::io::Result<()>,
    {
        match f(path.to_string()) {
            Ok(_) => {
                self.cache.remove(&path[0..path.rfind('/').unwrap()]);
            }
            Err(err) => {
                println!("error {}", err);
                out.error();
            }
        }
    }

    pub fn handle_command(&mut self, buf: [u8; 0x1000]) {
        let mut cmd = Command::from(buf);
        let head: &[u8] = cmd.read(4);
        if head != b"GLCI" {
            println!("Wrong magic");
            return;
        }
        let mut out: Command = Command::new();
        out.write_to(b"GLCO", 0); // OUT MAGIC

        match cmd.read_u32() {
            0 => {
                // GetDriveCount
                // not implemented
                out.write_u8(0);
            }
            1 => {
                // GetDriveInfo
                // not implemented
            }
            2 => {
                // StatPath
                self.stat(cmd, &mut out)
            }
            3 => {
                // GetFileCount
                self.get_count(cmd, &mut out, false);
            }
            4 => {
                // GetFile
                self.get_element(cmd, &mut out, false);
            }
            5 => {
                // GetDirectoryCount
                self.get_count(cmd, &mut out, true);
            }
            6 => {
                // GetDirectory
                self.get_element(cmd, &mut out, true);
            }
            7 => {
                // ReadFile
                self.read_file(&mut cmd, &mut out);
                return;
            }
            8 => {
                // WriteFile
                self.write_file(&mut cmd, &mut out);
            }
            9 => {
                // Create
                self.create(&mut cmd, &mut out);
            }
            10 => {
                // Delete
                self.delete(&mut cmd, &mut out)
            }
            11 => {
                // Rename
                self.rename(&mut cmd, &mut out)
            }
            12 => {
                // GetSpecialPathCount
                out.write_u8(1);
            }
            13 => {
                // GetSpecialPath
                out.write_string(&self.root);
                out.write_string(&self.root);
            }
            14 => {
                // SelectFile
                // not implemented
            }
            15 => {
                // Max
                // not implemented
            }
            _ => {}
        }

        self.switch
            .handle
            .write_bulk(
                self.switch.output.address,
                &out.buf,
                Duration::from_millis(100),
            )
            .expect("Unable to send data");
    }

    pub fn listen(mut self) {
        let mut buf: [u8; 0x1000] = [0; 0x1000];
        loop {
            if let Ok(_len) = self.switch.handle.read_bulk(
                self.switch.input.address,
                &mut buf,
                Duration::from_millis(100),
            ) {
                self.handle_command(buf);
            }
        }
    }
}
