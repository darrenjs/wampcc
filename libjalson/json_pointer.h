/*
 * Copyright (c) 2015 Darren Smith <jalson@darrenjs.net>
 *
 * Jalson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef __JSON_PATCH__
#define __JSON_PATCH__

#include <jalson/jalson.h>

namespace jalson
{

void apply_patch(json_value& doc, const json_array& patch);

}

#endif
