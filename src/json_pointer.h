/*
 * Copyright (c) 2015 Darren Smith <jalson@darrenjs.net>
 *
 * Jalson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef __JSON_PATCH__
#define __JSON_PATCH__

#include "jalson/jalson.h"

namespace wampcc
{

void apply_patch(json_value& doc, const json_array& patch);

const json_value * eval_json_pointer(const json_value& doc,
                                     const char* path);

json_value * eval_json_pointer(json_value& doc,
                               const char* path);

}

#endif
