#!/usr/bin/env python

# ****************************************************************************
#
# fkie_iop_wireshark_plugin
# Copyright 2019 Fraunhofer FKIE
# Author: Lukas Boes
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# ****************************************************************************


from __future__ import division, absolute_import, print_function, unicode_literals

import argparse
import sys

from fkie_iop_wireshark_plugin.parse_jsidl import Parse_JSIDL

'''
'''
if __name__ == "__main__":
  parser = argparse.ArgumentParser(description='file_manager')
  parser.add_argument('-i', "--input_path", help='Path to folder with JSIDL-files. If empty search for fkie_iop_builder ROS pacakge.')
  parser.add_argument('-o', "--output_path", help="path and name of the resulting LUA-script, Default: '~/.local/lib/wireshark/plugins/fkie_iop.lua'")
  parser.add_argument('-e', '--exclude', nargs='+', help='List with folder names to exclude from parsing')
  args = parser.parse_args()
  input_path = args.input_path
  output_path = args.output_path
  exclude = []
  if isinstance(args.exclude, list):
    exclude = args.exclude
  try:
    path = Parse_JSIDL(input_path, output_path, exclude)
  except KeyboardInterrupt:
    sys.exit()
