#include "replace_strings.h"

VALUE rb_mReplaceStrings;

RUBY_FUNC_EXPORTED void
Init_replace_strings(void)
{
  rb_mReplaceStrings = rb_define_module("ReplaceStrings");
}
