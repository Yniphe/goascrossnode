import ffi from 'ffi-napi';
import ref from 'ref-napi';


const lib = ffi.Library('build/shared/lib', {
    MyFunction: [ref.types.CString, []]
});

console.log({
    MyFunction: lib.MyFunction()
})