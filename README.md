# mssdk `get_token`
## reversing the get_token protocol

documentation only

some names below are only suppostions. offsets are from one specific
`libmetasec_ov.so` build and will probably move in another version.

---

## captured data

after capturing the request and looking at the decoded container, the payload
looks protobuf-ish. `get_token` reports mostly device info, device ids and sdk
metadata.

the observed data contains values similar to:

```text
device model / brand
android version
screen width + height
sdk version + release channel
application/package info
device id returned by device_register
android_id-like value
boot_id-like value
network-related fields
encrypted payload
```

the actual capture is not included here because it contains device-specific
ids, paths and addresses. use redacted values when documenting your own run:

```text
<device_id>
<android_id>
<boot_id>
<private_ip>
<redacted_payload>
```

## field guesses

the current mapping comes from comparing fields and changing test devices:

```text
outer field 8    -> business device id, returned by device_register
inner field 21   -> android_id
inner field 24   -> device-bound value, unchanged after reinstall
inner field 26   -> boot_id
```

field `24` stayed the same after uninstall/reinstall, but changed on another
device. that's why it looks device-bound. still, this isn't enough to identify
its exact Android source.

protobuf field numbers only make sense for the exact sdk build. don't assume
that `21`, `24` or `26` mean the same thing in a newer binary.

## request flow

the rough flow is:

```text
collect device + sdk values
        |
        v
build inner protobuf object
        |
        v
serialize object
        |
        v
compress serialized bytes
        |
        v
custom native vm / encryption routine
        |
        v
final byte transform
        |
        v
outer request container
```

the 6th outer field was the interesting one: it appeared to contain the actual
encrypted data.

to reproduce the analysis, compare lengths and buffers at each boundary. don't
start from the final request and guess everything backwards at once:

```text
java property
java byte array
native buffer
serialized protobuf
compressed buffer
vm output
final request field
```

---

## locating the device value

the first lead came from the native `base64_encode` path around `0xdea6c`.
the input came from a java byte array. the helper around `0xf7898` converts
that array into native data.

going one call above, around `0xf7878`, shows a java method call.

```text
call java: android.media.MediaDrm.getPropertyByteArray
```

the relevant stack in this build was:

```text
libmetasec_ov.so!0xf787c
libmetasec_ov.so!0xf7290
libmetasec_ov.so!0xf0028
libc++_shared.so!__call_once
libc.so!__pthread_start
```

### frida hook

basic hook used to print the java class + method name:

```js
const lib = Process.getModuleByName("libmetasec_ov.so");

Interceptor.attach(lib.base.add(0x10ab24), {
    onEnter() {
        const cls = getJavaClassName(this.context.x0, this.context.x2);
        const method = Memory.readCString(this.context.x3);
        console.log("call java: " + cls + "." + method);
    }
});
```

`getJavaClassName` is just a local helper. the hook is for locating the source
of the data, not for proving that `MediaDrm` returns the final device id.

---

## locating the encryption call

hooking `memcpy` and filtering by buffer length led to this sequence:

```asm
.text:000000000006aae4    bl   protobuf_to_buffer
.text:000000000006aae8    ldr  x0, [x19,#0x98]
.text:000000000006aaec    ldr  x22, [sp,#var_110]
.text:000000000006aaf0    bl   sub_490a4
.text:000000000006aaf4    mov  x3, x0
.text:000000000006ab08    bl   sub_11101c
```

`0x11101c` receives the serialized protocol data and produces the protected
result, directly or through an output object.

the function has a large stack frame, a helper table and a reference to data
around `0x161df0`. this looks like a small custom vm rather than a normal
standalone crypto function.

---

## vm notes

the useful parts of the long instruction listing are:

```text
x4  -> argument list pointer
x5  -> zero / vm base value
x6  -> native function table
x7  -> trampoline/helper address
x29 -> virtual stack area
```

the vm then does roughly this:

```text
save registers
initialize virtual stack
load input + metadata
call compression helper
dispatch instruction data from 0x161df0
call native helper functions
serialize the result
release temporary objects
return
```

useful locations from the trace:

```text
0x11101c  vm/encryption entry
0x161df0  opcode/data reference
0x0e1e60  compression-related helper
0x1110dc  repeated vm helper
0x1110e4  encryption-related helper
0x112854  protobuf/object serialization
0x10e230  first-field empty check
0x139e00  object copy-like helper
0x139b40  release-like helper
```

these are analysis labels, not official symbols.

---

## first 8 bytes

one part of the vm calculates two 32-bit values and joins them:

```py
data_first_4_bytes = w10.to_bytes(4, "little")
data_second_4_bytes = w8.to_bytes(4, "little")
return data_first_4_bytes + data_second_4_bytes
```

when translating arm32 arithmetic to python, mask values after operations:

```py
def u32(value):
    return value & 0xffffffff


w10 = u32(w10 - w17)
w11 = u32(w14 - w11)
w12 = u32(w12 + w2)

result = (
    w10.to_bytes(4, "little") +
    w8.to_bytes(4, "little")
)
```

the complete values of `w0..w17` depend on the vm state, so this snippet only
shows the important conversion rule.

---

## next 8 bytes

another block loads a constant from `0x161d60`, writes `0xb5` at offset `8`
and calls `0x12c35c`:

```asm
.text:0000000000113004    ldr   d0, [x8,#qword_161d60@pageoff]
.text:0000000000113008    mov   w8, #0xb5
.text:000000000011300c    mov   w1, #9
.text:0000000000113010    strb  w8, [x0,#8]
.text:0000000000113014    str   d0, [x0]
.text:0000000000113018    bl    loc_12c35c
```

the helper at `0x12c35c` is the final byte-level xor-like stage identified in
the notes.

---

## final xor stage

the recovered little-endian key for the tested build was:

```text
b5 20 91 e7 40 a0 e3 b6
```

the equivalent operation is:

```py
def encode_xor(data: bytes) -> bytes:
    key = bytes.fromhex("b5 20 91 e7 40 a0 e3 b6")
    return bytes(
        value ^ key[index % len(key)]
        for index, value in enumerate(data)
    )
```

since xor is symmetrical, applying it twice restores the input:

```py
sample = b"test data"
assert encode_xor(encode_xor(sample)) == sample
```

this is only the isolated byte operation. it does not implement the complete
sdk protocol, the protobuf schema, the compressor or the vm.

---

## local example

`example_protocol.py` contains a tiny offline example using fake bytes:

```py
from __future__ import annotations

XOR_KEY = bytes.fromhex("b5 20 91 e7 40 a0 e3 b6")


def xor_transform(data: bytes, key: bytes = XOR_KEY) -> bytes:
    if not key:
        raise ValueError("key must not be empty")
    return bytes(value ^ key[i % len(key)] for i, value in enumerate(data))


def main() -> None:
    payload = b"demo protobuf bytes"
    print(xor_transform(payload).hex(" "))


if __name__ == "__main__":
    main()
```

```bash
python example_protocol.py
```

the script doesn't load an apk, doesn't hook a process and doesn't make a
network request. it just demonstrates the byte operation.

---

## notes / open questions

```text
- complete protobuf schema not recovered
- field 24 source still needs confirmation
- compression format not fully identified
- vm opcode table not fully reconstructed
- offsets may change between builds
- xor constants may be build-specific
- server-side validation is outside this analysis
```

the useful conclusion so far is the pipeline:

```text
device values -> protobuf -> serialize -> compress -> custom native vm
-> final byte transform -> outer request field
```
