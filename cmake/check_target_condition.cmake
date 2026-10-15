include(CheckCSourceCompiles)

# Sets <var> to whether the C compiler, with the flags the build's targets get, satisfies the
# preprocessor expression <condition>, e.g.
#
#     check_target_condition(HAVE_AVX2 "defined(__x86_64__) && defined(__AVX2__)")
#
# This asks the compiler about its actual target, so it is right for cross builds and for 32-bit builds
# on 64-bit hosts, where the build host's architecture would be wrong.
#
# try_compile doesn't apply the directory's compile options, so they are passed explicitly: options
# such as -march from add_compile_options change the answer.  Generator expressions among them can't
# be passed this way and are skipped.  The check is redone on every configure because those options
# can differ between runs, and a cached result would then be stale.
function(check_target_condition var condition)
  get_directory_property(opts COMPILE_OPTIONS)
  list(FILTER opts EXCLUDE REGEX "\\$<")
  list(JOIN opts " " CMAKE_REQUIRED_FLAGS)
  unset(${var} CACHE)
  check_c_source_compiles("#if !(${condition})\n#error\n#endif\nint main(void) { return 0; }" ${var})
endfunction()
