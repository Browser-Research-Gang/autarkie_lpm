(tested on chrome commit: ee15fcc26a07eae50d5b03282d4cf7fe9f1caa47)

# Setup chrome codebase
change in 
testing/libfuzzer/fuzzer_test.gni
```
test(target_name) {
      forward_variables_from(invoker,
                             [
                               "cflags",
                               "cflags_cc",
                               "check_includes",
                               "defines",
                               "include_dirs",
                               "output_name",
                               "sources",
                               "libs",
                               "frameworks",
                             ])

+       # build_type = "debug"
+       build_type = "release"
+       ldflags = [
+         "-Wl,--allow-multiple-definition",
+         "-Wl,--whole-archive",
+         "/path/to/target/${build_type}/libautarkie_lpm.a" ,
+         "-Wl,--no-whole-archive",
+       ]
+       inputs = ["/path/to/target/${build_type}/libautarkie_lpm.a"]

```

and do the following in the same file:
```
if (defined(invoker.exclude_main) && invoker.exclude_main) {
-  test_deps += [ "//testing/libfuzzer:fuzzing_engine_no_main" ]
+ # test_deps += [ "//testing/libfuzzer:fuzzing_engine_no_main" ]
} else {
-  test_deps += [ "//testing/libfuzzer:fuzzing_engine_main" ]
+ # test_deps += [ "//testing/libfuzzer:fuzzing_engine_main" ]
}
```


make protobuf parse everything as binary since prost can only serialize to binary:
../../third_party/libprotobuf-mutator/src/src/libfuzzer/libfuzzer_macro.cc:
```
 auto result = ParseBinaryMessage(data, size, input);
//                       : ParseTextMessage(data, size, input);
```
# Building

gn args out/test:
```
use_external_fuzzing_engine=true
enable_mojom_fuzzer=true
is_debug = false
dcheck_always_on=false
is_asan=true

use_sanitizer_coverage=true
sanitizer_coverage_flags = "trace-pc-guard,trace-cmp
```

update in build.rs: add needed protos in targets array

update in lib.rs: set TargetType to the fuzzer input type (this should mostly be the exact same string you see in the DEFINE_PROTO_FUZZER definition)
```
cargo build --release
```
```
ninja -C out/test/ $TARGET_NAME
```