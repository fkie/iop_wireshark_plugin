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

import sys
import os
import errno
import fnmatch
import re

try:
  import jsidl_pyxb.jsidl as jsidl
except ImportError:
  # try ROS environment
  import fkie_iop_wireshark_plugin.jsidl_pyxb.jsidl as jsidl

import logging
logging.basicConfig(level=logging.INFO)

'''
The main of the ROS node for jsdil parser

@author Lukas Boes
'''


def LINE(line, depth):
  return '%s%s\n' % ('\t' * depth, line)

'''
If ROS is installed tries to find the path to given ROS package.
If it fails an empty string will be returned.
'''
def get_pkg_path(package_name):
  _get_pkg_path_var = None
  # try detect ROS package path
  try:
    try:
        import rospkg
        rp = rospkg.RosPack()
        _get_pkg_path_var = rp.get_path
    except ImportError:
      try:
        import roslib
        _get_pkg_path_var = roslib.packages.get_pkg_dir
      except ImportError:
        pass
    if _get_pkg_path_var is not None:
      return _get_pkg_path_var(package_name)
  except Exception:
    pass
  return ''


class Parse_JSIDL:
  
  TAB = '\t'
  
  def __init__(self, input_path=None, output_path=None, exclude=[]):
    if output_path is None:
      output_path = os.path.expanduser("~/.local/lib/wireshark/plugins/fkie_iop.lua")
      logging.info("Write lua to default path: %s%s" % (output_path, os.getcwd()))
    else:
      logging.info("Write lua to: %s" % (output_path))
    try:
      # create output directory if not exists
      os.makedirs(os.path.dirname(output_path))
    except OSError as e:
      if e.errno != errno.EEXIST:
        raise
    # open lua file to write parsed messages
    with open(output_path, 'w+') as self.lua_file:
      # copy template script to lua plugin
      with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fkie_iop_template.lua")) as f_input:
        for line in f_input.readlines():
            self.lua_file.write(line)
      if input_path is None:
        input_path = get_pkg_path("fkie_iop_builder")
        input_path = os.path.join(input_path, "jsidl")
        logging.info("Read from default jsidl input path: %s" % (input_path))
      else:
        logging.info("Read jsidl files from: %s" % (input_path))

      # create a set with all xml files found in input_path
      self.xml_files = set()
      self.doc_files = {}
      for root, _dirnames, filenames in os.walk(input_path):
        subdirs = root.replace(input_path, '').split(os.path.sep)
        if not (set(subdirs) & set(exclude)):
          for filename in fnmatch.filter(filenames, '*.xml'):
            xmlfile = os.path.join(root, filename)
            self.xml_files.add(os.path.join(root, xmlfile))
        else:
          logging.debug("Skip folder: %s" % root)
      current_idx = 0  # counter for debug output
      self._message_count = 0
      self._message_failed = []
      self._message_ids = dict()
      self._message_doubles = []
      # parse all files found in input_path
      for xmlfile in sorted(self.xml_files):
        current_idx += 1
        logging.debug("Parse [%d/%d]: %s" % (current_idx, len(self.xml_files), xmlfile))
        self.parse_jsidl_file(xmlfile)
      logging.info("%d messages found" % self._message_count)
      if self._message_failed:
        logging.warning("Parse errors in %d messages: \n\t%s" % (len(self._message_failed), '\n\t'.join(["%s: %s" % (msgname, fname) for msgname, fname in self._message_failed])))
      if self._message_doubles:
        logging.warning("Skipped %d messages, their name was already been parsed. See warnings for details!" % (len(self._message_doubles)))

  def parse_jsidl_file(self, filename):
    js = self._get_doc(filename)
    if not hasattr(js, 'message_def'):
      logging.debug("No 'message_def' found!")
      return
    self.dirname = os.path.dirname(filename)
    logging.debug("current directory: %s" % self.dirname)

    # parse message definitions
   
    for counter in range(len(js.message_def)):
      try:
        logging.debug("--- MESSAGE %d/%d  ---  FILE %s ---" % (counter + 1, len(js.message_def), filename))
        jsmsg = js.message_def[counter]
        dissector_name = "%s_%s" % (jsmsg.name.lower(), jsmsg.message_id.encode('hex'))
        if jsmsg.message_id in self._message_ids:
          self._message_doubles.append("%s(%s)" % (jsmsg.name, jsmsg.message_id.encode('hex')))
          logging.warning("skip message with already parsed message ID: %s, msg_id: %s,\n  file: %s,\n  first found in %s" %(jsmsg.name, jsmsg.message_id.encode('hex'), filename, self._message_ids[jsmsg.message_id]))
          continue
        self._not_parsed = []
        self._current_msg_name = jsmsg.name
        self._message_ids[jsmsg.message_id] = filename
        logging.debug("Parse message: %s, msg_id: %s" %(jsmsg.name, jsmsg.message_id.encode('hex')))
        self._message_count += 1
        

        self.data_string = LINE('%s = Proto("%s", "%s 0x%s")' % (dissector_name, dissector_name, jsmsg.name, jsmsg.message_id.encode('hex')), 0)
        self.data_string += LINE("function %s.dissector(buffer, pinfo, tree)" % dissector_name, 0)
        self.data_string += LINE("-- %s" % filename, 1)
        self.data_string += LINE("local bufidx = 0", 1)
        self.data_string += LINE("messageid = buffer(bufidx, 2):le_uint()", 1)
        self.data_string += LINE('local tree_msg = tree:add(pf_message_name, buffer(), "%s", string.format("%s, MessageID: %%04X, %%d bytes", messageid, buffer:len()))' % (jsmsg.name, jsmsg.name), 1)
        # update column info
        self.data_string += LINE('pinfo.cols.info:set(string.format("%%s %%s", tostring(pinfo.cols.info), "%s"))' % jsmsg.name, 1)
        # add header
        self.data_string += self.find_header(jsmsg, filename)
        # add body
        if jsmsg.body.orderedContent():
          self.data_string += LINE('local body_tree = tree_msg:add(buffer(bufidx, buffer:len() - bufidx), "Body")', 1)
          for bc in jsmsg.body.orderedContent():
            self.data_string += self.parse_element(bc, "body", filename)
        if self._not_parsed:
          self.data_string += LINE('local not_parsed_tree = tree_msg:add_expert_info(PI_UNDECODED, PI_WARN, "this message contains fields not included into this dissector %s. Field values could be wrong!")' % str(self._not_parsed), 1)
        # close dissector
        self.data_string += LINE("end", 0)
        self.data_string += LINE("messagetable:add(0x%s, %s)\n" % (((jsmsg.message_id).encode('hex')).upper(), dissector_name), 0)
        # write into the file only if no Exception occurs
        self.lua_file.write(self.data_string)
      except Exception:
        import traceback
        logging.warning(traceback.format_exc())
        self._message_failed.append((jsmsg.name, filename))

  def parse_element(self, element, lua_var_prefix, filename, depth=1, list_index_str=''):
    result_str = ""
    # check for optional parameter and add an if-statement if it is  true
    optional = hasattr(element.value, "optional") and str(element.value.optional) == "true"
    if optional:
      result_str += LINE('if (bitAND(%s_pv, %s_pv_count) > 0) then' % (lua_var_prefix, lua_var_prefix), depth)
      depth += 1
    elname = element.elementDeclaration.name().localName()
    if elname == "array":
      result_str += self.parse_array(element, lua_var_prefix, filename, depth)
    elif elname == "bit_field":
      result_str += self.parse_bit_field(element, lua_var_prefix, filename, depth)
    elif elname == "fixed_field":
      result_str += self.parse_fixed_field(element, lua_var_prefix, filename, depth)
    elif elname == "fixed_length_string":
      result_str += self.parse_fixed_length_string(element, lua_var_prefix, filename, depth)
    elif elname == "list":
      result_str += self.parse_list(element, lua_var_prefix, filename, depth)
    elif elname == "presence_vector":
      result_str += self.parse_presence_vector(element, lua_var_prefix, filename, depth)
    elif elname in ["record", "sequence"]:
      result_str += self.parse_record(element, lua_var_prefix, filename, depth, list_index_str=list_index_str)
    elif elname == "variable_length_field":
      result_str += self.parse_variable_length_field(element, lua_var_prefix, filename, depth)
    elif elname == "variable_length_string":
      result_str += self.parse_variable_length_string(element, lua_var_prefix, filename, depth)
    elif elname == "variant":
      result_str += self.parse_variant(element, lua_var_prefix, filename, depth, list_index_str=list_index_str)
    elif elname == "declared_array":
      result_str += self.parse_declared_array(element, lua_var_prefix, filename, depth)
    elif elname == "declared_bit_field":
      result_str += self.parse_declared_bit_field(element, lua_var_prefix, filename, depth)
    elif elname == "declared_fixed_field":
      result_str += self.parse_declared_fixed_field(element, lua_var_prefix, filename, depth)
    elif elname == "declared_list":
      result_str += self.parse_declared_list(element, lua_var_prefix, filename, depth)
    elif elname == "declared_record":
      result_str += self.parse_declared_record(element, lua_var_prefix, filename, depth)
    elif elname == "variable_format_field":
      result_str += self.parse_variable_format_field(element, lua_var_prefix, filename, depth)
    elif elname == "declared_variable_length_string":
      result_str += self.parse_declared_variable_length_string(element, lua_var_prefix, filename, depth)
    else:
      logging.info("skipped '%s' -- no parser implemented, message: %s, file: %s" % (elname, self._current_msg_name, filename))
      self._not_parsed.append(elname)
    if optional:
      result_str += LINE("end", depth - 1)
      result_str += LINE('%s_pv_count = %s_pv_count + 1' % (lua_var_prefix, lua_var_prefix), depth - 1)
    return result_str

  def parse_array(self, element, lua_var_prefix, filename, depth=1, declared_name='', declared_comment=''):
    result = ""
    name = self.get_name(element, force=declared_name)
    comment = self.get_comment(element, force=declared_comment)
    # parse dimensions
    dimension = ()  # name, count, comment, dimension tuple or empty tuple
    for rc in element.value.orderedContent():
      if rc.elementDeclaration.name().localName() == "dimension":
        size = 1
        dim_comment = self.get_comment(rc)
        if hasattr(rc.value, "size"):
          size = self._to_int(rc.value.size, filename)
        dim_name = rc.value.name
        dimension = (dim_name, size, dim_comment, dimension)
    string_prefix = "%s_%s" % (lua_var_prefix, element.value.name)
    result += LINE('local %s_tree = %s_tree:add("%s%s")' % (string_prefix, lua_var_prefix, name, comment), depth)
    result += self._parse_array_wo_dimension(element, dimension, string_prefix, filename, depth + 1)
    return result

  def _parse_array_wo_dimension(self, element, dimension, lua_var_prefix, filename, depth=1):
    dim_prefix_str = "%s_%s" % (lua_var_prefix, dimension[0])
    result = ''
    result += LINE('local %s_tree = %s_tree:add("%s [%d]%s")' % (dim_prefix_str, lua_var_prefix, dimension[0], dimension[1], dimension[2]), depth)
    result += LINE('for %s_i = 1, %d do' % (dim_prefix_str, dimension[1]), depth)
    if dimension[3]:
      result += self._parse_array_wo_dimension(element, dimension[3], dim_prefix_str, filename, depth + 1)
    for rc in element.value.orderedContent():
      if rc.elementDeclaration.name().localName() != "dimension":
        result += self.parse_element(rc, dim_prefix_str, filename, depth + 1)
    result += LINE('end', depth)
    return result

  def parse_record(self, element, lua_var_prefix, filename, depth=1, declared_name='', declared_comment='', list_index_str=''):
    result = ""
    name = self.get_name(element, force=declared_name)
    comment = self.get_comment(element, force=declared_comment)
    string_prefix = lua_var_prefix
    if lua_var_prefix != 'header':
      # create a subtree for record or sequence
      string_prefix = "%s_%s" % (lua_var_prefix, name)
      if list_index_str:
        # add list index to the name
        result += LINE('local %s_tree = %s_tree:add(string.format("%s_%%d%s", %s))' % (string_prefix, lua_var_prefix, name, comment, list_index_str), depth)
      else:
        result += LINE('local %s_tree = %s_tree:add("%s%s")' % (string_prefix, lua_var_prefix, name, comment), depth)
    for rc in element.value.orderedContent():
      result += self.parse_element(rc, string_prefix, filename, depth)
    return result

  def parse_variant(self, element, lua_var_prefix, filename, depth=1, list_index_str=''):
    result = ""
    name = self.get_name(element)
    comment = self.get_comment(element)
    string_prefix = "%s_%s" % (lua_var_prefix, name)
    if list_index_str:
      # add list index to the name
      result += LINE('local %s_tree = %s_tree:add(string.format("%s_%%d%s", %s))' % (string_prefix, lua_var_prefix, name, comment, list_index_str), depth)
    else:
      result += LINE('local %s_tree = %s_tree:add("%s%s")' % (string_prefix, lua_var_prefix, name, comment), depth)
    vtag_field = element.value.orderedContent()[0]
    if vtag_field.elementDeclaration.name().localName() != "vtag_field":
      raise Exception("Variant should contain vtag_field!")
    vtag_str, data_string, type_len = self.parse_vtag_field(vtag_field, string_prefix, filename, depth)
    result += data_string
    result += LINE('local %s_index = %s' % (lua_var_prefix, vtag_str), depth)
    result += LINE("bufidx = bufidx + %d" % type_len, depth)
    var_counter = 0
    for rc in element.value.orderedContent()[1:]:
      result += LINE('if (%s_index == %s) then' % (lua_var_prefix, var_counter), depth)
      result += self.parse_element(rc, string_prefix, filename, depth + 1)
      result += LINE("end", depth)
      var_counter += 1
    return result
  
  def parse_variable_format_field(self, element, lua_var_prefix, filename , depth=1):
    result = ""
    q_list = ""
    name = self.get_name(element)
    variable_format_field = element.value.orderedContent()[0]
    if variable_format_field.elementDeclaration.name().localName() != "format_field":
      raise Exception("JAUS MESSAGE should contain format_field!")
    if variable_format_field.value.format_enum:
          q_list = ', '.join(['[%d] = "%s"' % (format_enum.index, self.check_spaces(format_enum.field_format)) for format_enum in variable_format_field.value.format_enum])
    count_field = element.value.orderedContent()[1]
    if count_field.elementDeclaration.name().localName() != "count_field":
      raise Exception("JAUS MESSAGE should contain count_field!")
    string_prefix = "%s_%s" % (lua_var_prefix, element.value.name)
    count_str, data_string, count_type_len = self.parse_count_field(count_field, lua_var_prefix, filename, depth)
    buffer_str = "buffer(bufidx, %d)" % (count_type_len)
    result += LINE("local format_field_set = {%s}" % q_list, depth)
    result += LINE("local format_field_value = buffer(bufidx, 1):le_uint()", depth)
    result += LINE("bufidx = bufidx + 1", depth)
    result += LINE('%s_tree:add(%s, string.format("%s: %%s [%%s] -- (%%d)",format_field_value, format_field_set[format_field_value], buffer(bufidx, 2):le_uint()))' % (lua_var_prefix, buffer_str, name), depth)

    result += LINE('local %s_count = %s' % (lua_var_prefix, count_str), depth)
    result += LINE("bufidx = bufidx + %d" % (count_type_len), depth)
    result += LINE('submsgid = buffer(bufidx, 2):le_uint()', depth)
    result += LINE('local subpacket_dissector = messagetable:get_dissector(submsgid)', depth)
    result += LINE('if subpacket_dissector ~= nil then', depth)
    result += LINE('subid_str = subpacket_dissector(buffer(bufidx, %s_count):tvb(), pinfo, tree)' % (lua_var_prefix), depth + 1)
    result += LINE('else', depth)

    result += LINE('local %s_tree = %s_tree:add(pf_sub_messageid, buffer(bufidx, 2), submsgid, string.format("Included Message, MessageID: 0x%%04X, %%d bytes", submsgid, %s_count))' % (string_prefix, lua_var_prefix, lua_var_prefix), depth)
    result += LINE('%s_tree:append_text(", unknown message")' % string_prefix, depth + 1)
    result += LINE('end', depth)
    result += LINE("bufidx = bufidx + %s_count" % (lua_var_prefix), depth)
    return result
  
  def parse_vtag_field(self, element, lua_var_prefix, filename, depth=1):
    field_type_unsigned = self.get_field_type_length(element.value.field_type_unsigned)
    min_count = element.value.min_count
    max_count = element.value.max_count
    vtag_str = "buffer(bufidx, %d):le_uint()" % (field_type_unsigned)
    data_str = LINE('%s_tree:add(buffer(bufidx, %d), string.format("vtag: %%d, min_count: %s, max_count: %s", %s))' % (lua_var_prefix, field_type_unsigned, str(min_count), str(max_count), vtag_str), depth)
    return vtag_str, data_str, field_type_unsigned

  def parse_bit_field(self, element, lua_var_prefix, filename, depth=1, declared_name='', declared_comment=''):
    result = ""
    name = self.get_name(element, force=declared_name)
    q_type_length = self.get_field_type_length(element.value.field_type_unsigned)
    comment = self.get_comment(element, "(%s)" % element.value.field_type_unsigned, force=declared_comment)
    string_prefix = "%s_%s" % (lua_var_prefix, element.value.name)
    buffer_str = "buffer(bufidx, %d)" % (q_type_length)
    result += LINE('local %s_buf = %s' % (string_prefix, buffer_str), depth)
    result += LINE('local %s_tree = %s_tree:add(%s, string.format("%%s = %s: 0x%%X %s", bitstr(%s_buf:le_uint(), %d), %s_buf:le_uint()))' % (string_prefix, lua_var_prefix, buffer_str, name, comment, string_prefix, q_type_length * 8, string_prefix), depth)
    # parse subfields
    for rc in element.value.orderedContent():
      if rc.elementDeclaration.name().localName() == "sub_field":
        if hasattr(rc.value, "scale_range"):
          logging.warning("skipped 'scale_range' in 'sub_field' -- not implemented, message: %s, file: %s" % (self._current_msg_name, filename))
        if hasattr(rc.value, "bit_range"):
          from_index = rc.value.bit_range.from_index
          to_index = rc.value.bit_range.to_index
          result += LINE('%s_tree:add(%s, string.format("%%s = %s: %%d", bitstr_part(%s_buf:le_uint(), %d, %s, %s), bitVal(%s_buf:le_uint(), %s, %s)))' % (string_prefix, buffer_str, rc.value.name, string_prefix, q_type_length * 8, from_index, to_index, string_prefix, from_index, to_index), depth)
        else:
          logging.warning("no 'bit_range' in 'sub_field' found, message: %s, file: %s" % (self._current_msg_name, filename))
    result += LINE("bufidx = bufidx + %d" % q_type_length, depth)
    return result

  def parse_fixed_length_string(self, element, lua_var_prefix, filename, depth=1, declared_name='', declared_comment=''):
    result = ""
    name = self.get_name(element, force=declared_name)
    # read string_length first
    if hasattr(element.value, "string_length"):
      string_length = self._to_int(element.value.string_length, filename)
      result += LINE('%s_tree:add(buffer(bufidx, %d), string.format("%s [%d]: %%s", buffer(bufidx, %d):string()))' % (lua_var_prefix, string_length, name, string_length, string_length), depth)
      result += LINE("bufidx = bufidx + %d" % (string_length), depth)
    else:
      logging.warning("no 'string_length' in 'fixed_length_string' found, message: %s, file: %s" % (self._current_msg_name, filename))
    return result

  def parse_variable_length_field(self, element, lua_var_prefix, filename, depth=1):
    result = ""
    if element.value.field_format == "JAUS MESSAGE":
      # read count field first
      count_field = element.value.orderedContent()[0]
      if count_field.elementDeclaration.name().localName() != "count_field":
        raise Exception("JAUS MESSAGE should contain count_field!")
      string_prefix = "%s_%s" % (lua_var_prefix, element.value.name)
      count_str, data_string, count_type_len = self.parse_count_field(count_field, lua_var_prefix, filename, depth)
      result += data_string
      result += LINE('local %s_count = %s' % (lua_var_prefix, count_str), depth)
      result += LINE("bufidx = bufidx + %d" % (count_type_len), depth)
      result += LINE('if %s_count > buffer:len() - bufidx then' % (lua_var_prefix), depth)
      result += LINE('%s_count = buffer:len() - bufidx' % (lua_var_prefix), depth + 1)
      result += LINE('end', depth)
      result += LINE('submsgid = buffer(bufidx, 2):le_uint()', depth)
      result += LINE('local subpacket_dissector = messagetable:get_dissector(submsgid)', depth)
      result += LINE('if subpacket_dissector ~= nil then', depth)
      result += LINE('subid_str = subpacket_dissector(buffer(bufidx, %s_count):tvb(), pinfo, tree)' % (lua_var_prefix), depth + 1)
      result += LINE('else', depth)
      # if it is an unknown message, create an info entry
      result += LINE('local %s_tree = %s_tree:add(pf_sub_messageid, buffer(bufidx, 2), submsgid, string.format("Included Message, MessageID: 0x%%04X, %%d bytes", submsgid, %s_count))' % (string_prefix, lua_var_prefix, lua_var_prefix), depth)
      result += LINE('%s_tree:append_text(", unknown message")' % string_prefix, depth + 1)
      result += LINE('end', depth)
      result += LINE("bufidx = bufidx + %s_count" % (lua_var_prefix), depth)
    return result

  def parse_count_field(self, element, lua_var_prefix, filename, depth=1):
    field_type_unsigned = self.get_field_type_length(element.value.field_type_unsigned)
    min_count = element.value.min_count
    max_count = element.value.max_count
    count_str = "buffer(bufidx, %d):le_uint()" % (field_type_unsigned)
    data_str = LINE('%s_tree:add(buffer(bufidx, %d), string.format("Count: %%d, min_count: %s, max_count: %s", %s))' % (lua_var_prefix, field_type_unsigned, str(min_count), str(max_count), count_str), depth)
    return count_str, data_str, field_type_unsigned

  def parse_variable_length_string(self, element, lua_var_prefix, filename, depth=1, declared_name='', declared_comment=''):
    data_string = ""
    name = self.get_name(element, force=declared_name)
    _comment = self.get_comment(element, force=declared_comment)
    # read count field first
    count_field = element.value.orderedContent()[0]
    if count_field.elementDeclaration.name().localName() != "count_field":
      raise Exception("variable_length_string should contain count_field!")
    string_prefix = "%s_%s" % (lua_var_prefix, name)
    count_str, data_string, count_type_len = self.parse_count_field(count_field, string_prefix, filename, depth)
    result = ""
    result += LINE('local %s_tree = %s_tree:add(buffer(bufidx, %d + %s), string.format("%s[%%d]: %%s", %s, buffer(bufidx + %d, %s):string()))' % (string_prefix, lua_var_prefix, count_type_len, count_str, name, count_str, count_type_len, count_str), depth)
    result += data_string
    result += LINE("bufidx = bufidx + %d + %s" % (count_type_len, count_str), depth)
    return result

  def parse_list(self, element, lua_var_prefix, filename, depth=1, declared_name='', declared_comment=''):
    data_string = ""
    name = self.get_name(element, force=declared_name)
    comment = self.get_comment(element, force=declared_comment)
    list_prefix = "%s_%s" % (lua_var_prefix, name)
    result = LINE("local bufidx_start_%s = bufidx" % lua_var_prefix, depth)
    # read count field first
    count_field = element.value.orderedContent()[0]
    if count_field.elementDeclaration.name().localName() != "count_field":
      raise Exception("count_field should be first element in the list!")
    count_str, data_string, count_type_len = self.parse_count_field(count_field, list_prefix, filename, depth)
    # add list elements
    data_string += LINE("local %s_count = %s" % (list_prefix, count_str), depth)
    data_string += LINE("bufidx = bufidx + %d" % count_type_len, depth)
    data_string += LINE('for %s_counter=1,%s_count do' % (lua_var_prefix, list_prefix), depth)
    for list_line in element.value.orderedContent():
      if list_line.elementDeclaration.name().localName() != "count_field":
        data_string += self.parse_element(list_line, list_prefix, filename, depth + 1, list_index_str="%s_counter - 1" % lua_var_prefix)
    data_string += LINE('end', depth)
    result += LINE('local %s_tree = %s_tree:add(buffer(bufidx_start_%s, buffer:len() - bufidx_start_%s), "%s %s")' % (list_prefix, lua_var_prefix, lua_var_prefix, lua_var_prefix, name, comment), depth)
    result += data_string
    return result

  def parse_presence_vector(self, element, lua_var_prefix, filename, depth=1):
    result = ""
    type_len = self.get_field_type_length(element.value.field_type_unsigned)
    result += LINE('local %s_pv = buffer(bufidx, %d):le_uint()' % (lua_var_prefix, type_len), depth)
    result += LINE('local %s_pv_count = 0' % (lua_var_prefix), depth)
    result += LINE('%s_tree:add(buffer(bufidx, %d), string.format("%s: %%s", bitstr(buffer(bufidx, %d):le_uint(), %d * 8)))' % (lua_var_prefix, type_len, "Presence Vector", type_len, type_len), depth)
    result += LINE("bufidx = bufidx + %d" % type_len, depth)
    return result

  def parse_fixed_field(self, element, lua_var_prefix, filename, depth=1, declared_name='', declared_comment=''):
    result = ""
    name = self.get_name(element, force=declared_name)
    q_type_length = self.get_field_type_length(element.value.field_type)
    comment = self.get_comment(element, "(%s)" % element.value.field_type, force=declared_comment)
    value_set = ''
    scale_factor = bias = None
    for valset in element.value.orderedContent():
      if valset.elementDeclaration.name().localName() == "value_set":
        value_set = self.parse_value_set(valset, depth)
      elif valset.elementDeclaration.name().localName() == "scale_range":
        scale_factor, bias = self.parse_scale_range(valset, q_type_length, lua_var_prefix, filename, depth)
    if lua_var_prefix == "header":
      result += LINE('tree_msg:add(pf_messageid, buffer(bufidx, %d), messageid, string.format(\'Header, %s: 0x%%04X %s\', messageid))' % (q_type_length, name, comment), depth)
    else:
      buffer_str = "buffer(bufidx, %d)" % (q_type_length)
      if value_set:
        result += value_set
        result += LINE("local value_id, value_name = (value_set[%s:le_uint()])" % (buffer_str), depth)
        result += LINE('%s_tree:add(%s, string.format("%s: %%d [%%s] -- (%s)", %s:le_uint(), value_id))' % (lua_var_prefix, buffer_str, name, element.value.field_type, buffer_str), depth)
      elif scale_factor is not None:
        # print scaled float values
        result += LINE('%s_tree:add(%s, string.format("%s: %%.4f (scaled) %s", %s:le_uint() * %.12f + (%.12f)))' % (lua_var_prefix, buffer_str, name, comment, buffer_str, scale_factor, bias), depth)
      else:
        result += LINE('%s_tree:add(%s, string.format("%s: %%d %s", %s:le_uint()))' % (lua_var_prefix, buffer_str, name, comment, buffer_str), depth)
    result += LINE("bufidx = bufidx + %d" % q_type_length, depth)
    return result

  def parse_declared_array(self, element, lua_var_prefix, filename, depth=1):
    js, infile = self._resolve_type_ref(element.value.declared_type_ref, "array", filename)
    return self.parse_array(js, lua_var_prefix, infile, depth, element.value.name, self.get_comment(element))

  def parse_declared_bit_field(self, element, lua_var_prefix, filename, depth=1):
    js, infile = self._resolve_type_ref(element.value.declared_type_ref, "bit_field", filename)
    return self.parse_bit_field(js, lua_var_prefix, infile, depth, element.value.name, self.get_comment(element))

  def parse_declared_fixed_field(self, element, lua_var_prefix, filename, depth=1):
    js, infile = self._resolve_type_ref(element.value.declared_type_ref, "fixed_field", filename)
    return self.parse_fixed_field(js, lua_var_prefix, infile, depth, element.value.name, self.get_comment(element))

  def parse_declared_list(self, element, lua_var_prefix, filename, depth=1):
    js, infile = self._resolve_type_ref(element.value.declared_type_ref, "list", filename)
    return self.parse_list(js, lua_var_prefix, infile, depth, element.value.name, self.get_comment(element))

  def parse_declared_record(self, element, lua_var_prefix, filename, depth=1):
    js, infile = self._resolve_type_ref(element.value.declared_type_ref, "record", filename)
    return self.parse_record(js, lua_var_prefix, infile, depth, element.value.name, self.get_comment(element))

  def parse_declared_variable_length_string(self, element, lua_var_prefix, filename, depth=1):
    js, infile = self._resolve_type_ref(element.value.declared_type_ref, "variable_length_string", filename)
    return self.parse_variable_length_string(js, lua_var_prefix, infile, depth, element.value.name, self.get_comment(element))

  def parse_scale_range(self, element, q_type_length, lua_var_prefix, filename, depth):
    bias = self._to_float(element.value.real_lower_limit, filename)
    real_upper_limit = self._to_float(element.value.real_upper_limit, filename)
    scale_factor = (real_upper_limit - bias) / (2**(q_type_length * 8) - 1)
    return scale_factor, bias

  def parse_value_set(self, element, depth):
    result = ""
    q_list = ""
    if element.value.value_enum:
        q_list = ', '.join(['[%d] = "%s"' % (val_enum.enum_index, self.check_spaces(val_enum.enum_const)) for val_enum in element.value.value_enum])

    # rang_interpretation = []
    # for val_range in element.value.value_range:
    #     try:
    #       rang_interpretation.append(self.check_spaces(str(val_range.interpretation)))
    #     except Exception:
    #       pass
    # rang_interpretation = '; '.join(rang_interpretation)
    result += LINE("local value_set = {%s}" % q_list, depth)
    return result

  def find_header(self, jsmsg, filename):
      result = ""
      for rc in jsmsg.orderedContent():
        elname = rc.elementDeclaration.name().localName()
        if elname == "header":
          for header in jsmsg.header.orderedContent():
            result = self.parse_element(header, "header", filename=filename)
        elif elname == "declared_header":
          # try to resolve header reference
          js, filename = self._resolve_type_ref(rc.value.declared_type_ref, "header", filename=filename)
          for header in js.value.orderedContent():
            result = self.parse_element(header, "header", filename=filename)
      return result

  def get_field_type_length(self, field_type):
    f_types = {'byte':1, 'short integer':2, 'integer':4, 'long integer':8, 'unsigned byte':1, 'unsigned short integer':2, 'unsigned integer':4, 'unsigned long integer':8, 'float':4, 'long float':8}
    return f_types.get(field_type)

  def get_name(self, element, force=''):
    if force:
      return force
    return element.value.name

  def get_comment(self, element, prefix='', sep='--', force=''):
    if force:
      return force
    comment = ''
    if element.value.interpretation:
      comment = self.check_spaces(element.value.interpretation)
      if prefix:
        comment = "%s %s" % (prefix, comment)
      if comment and sep:
        comment = '%s %s' % (sep, comment)
    return comment

  def check_spaces(self, data):
    if data:
      return " ".join(data.split())
    return ''

  def _resolve_type_ref(self, declared_type_ref, tagname, filename):
    js = self._get_doc(filename)
    path_list = declared_type_ref.split(".")
    # by one element we have the name of referenced item, search in `js` for tags with `tagname`
    if len(path_list) == 1:
      for tag in js.orderedContent():
        if tagname == tag.elementDeclaration.name().localName() and path_list[0] == tag.value.name:
          return tag, filename
    else:
      # read first all defined references
      for declared_ref in js.declared_type_set_ref:
        if path_list[0] == declared_ref.name:
          declared_id = declared_ref.id
          declared_vers = declared_ref.version
          logging.debug("declared_type_set_ref: id='%s', version='%s'" % (declared_id, declared_vers))
          ref_js = None
          # try to find file with referenced set
          inpath = None
          for xml_file in self._local_first_xml_files():
            ref_js = self._get_doc(xml_file)
            if ref_js.id == declared_id and ref_js.version == declared_vers:
              logging.debug("found referenced type '%s v%s' in %s" % (declared_id, declared_vers, xml_file))
              inpath = xml_file
              break
          if ref_js is None:
            raise Exception("Type reference not found: id='%s', version='%s'" % (declared_id, declared_vers))
          else:
            return self._resolve_type_ref('.'.join(path_list[1:]), tagname, inpath)
    raise Exception("declared_type_ref '%s' not found in %s" % (declared_type_ref, filename))

  def _resolve_const_ref(self, name, filename):
    js = self._get_doc(filename)
    path_list = name.split(".")
    # by one element we have the name of referenced item, search in `js` for tags with `tagname`
    if len(path_list) == 1:
      for tag in js.orderedContent():
        if 'const_def' == tag.elementDeclaration.name().localName() and path_list[0] == tag.value.name:
          return tag.value.const_value, tag.value.const_type, filename
    else:
      # read first all defined references
      for declared_const_ref in js.declared_const_set_ref:
        if path_list[0] == declared_const_ref.name:
          declared_id = declared_const_ref.id
          declared_vers = declared_const_ref.version
          logging.debug("declared_const_ref: id='%s', version='%s'" % (declared_id, declared_vers))
          ref_js = None
          # try to find file with referenced set
          inpath = None
          for xml_file in self._local_first_xml_files():
            ref_js = self._get_doc(xml_file)
            if ref_js.id == declared_id and ref_js.version == declared_vers:
              logging.debug("found referenced const '%s v%s' in %s" % (declared_id, declared_vers, xml_file))
              inpath = xml_file
              break
          if ref_js is None:
            raise Exception("declared_const_ref not found: id='%s', version='%s'" % (declared_id, declared_vers))
          else:
            return self._resolve_const_ref('.'.join(path_list[1:]), inpath)
    raise Exception("declared_const_ref '%s' not found in %s" % (name, filename))

  def _local_first_xml_files(self):
    # search in current directory first!
    return [f for f in self.xml_files if f.startswith(self.dirname) ] + [f for f in self.xml_files if not f.startswith(self.dirname)]

  def _to_float(self, value, filename):
    try:
      return float(value)
    except ValueError:
      rval = value
      # find variables in values
      re_vars = re.compile(r"(?P<name>[a-zA-Z]+[^\*\-\+\/]*)")
      for var in re_vars.findall(value):
        # replace all known variables
        const_val, _const_type, _filename = self._resolve_const_ref(var, filename)
        rval = rval.replace(var, const_val)
      # try to convert again
      ret = float(eval(rval))
      logging.debug("resolved '%s' to '%s', evaluated to %.6f" % (value, rval, ret))
      return ret

  def _to_int(self, value, filename):
    try:
      return int(value)
    except ValueError:
      rval = value
      # find variables in values
      re_vars = re.compile(r"(?P<name>[a-zA-Z]+[^\*\-\+\/]*)")
      for var in re_vars.findall(value):
        # replace all known variables
        const_val, _const_type, _filename = self._resolve_const_ref(var, filename)
        rval = rval.replace(var, const_val)
      # try to convert again
      ret = int(eval(rval))
      logging.debug("resolved '%s' to '%s', evaluated to %d" % (value, rval, ret))
      return ret

  def _get_doc(self, path):
    try:
      return self.doc_files[path]
    except KeyError:
      with open(path) as f:
        data = f.read()
        jsdoc = jsidl.CreateFromDocument(data)
        self.doc_files[path] = jsdoc
        return jsdoc
    return None
