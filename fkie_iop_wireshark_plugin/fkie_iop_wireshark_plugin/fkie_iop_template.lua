proto = Proto("IOP", "Interoperability Profiles");

pf_messageid      = ProtoField.uint16("iop.message_id",       "Message ID",    base.HEX)
pf_message_name   = ProtoField.string("iop.message_name",     "Message Name",  base.STRING)
pf_sub_messageid  = ProtoField.uint16("iop.event.message_id", "Event Message ID", base.HEX)
pf_msg_type       = ProtoField.uint8("iop.message_type",      "message_type",  base.HEX, nil, 0x3F)
pf_hc_flags       = ProtoField.uint8("iop.hc_flags",          "hc_flags",      base.HEX, nil, 0xC0)
pf_flags          = ProtoField.uint8("iop.flags",             "flags",         base.HEX, nil, 0xFF)
pf_f_priority     = ProtoField.uint8("iop.flags.priority",    "Priority",      base.HEX,
    {[0]="Low",[1]="Standard",[2]="High",[3]="Safety Critical"}, 0x03)
pf_f_bcast        = ProtoField.uint8("iop.flags.bcast",       "Broadcast",     base.HEX,
    {[0]="No Broadcast",[1]="Local Broadcast",[2]="Global Broadcast"}, 0x0C)
pf_f_acknak       = ProtoField.uint8("iop.flags.acknack",     "Acknak",        base.HEX,
    {[0]="No response required",[1]="Response required",
     [2]="Message negative acknowledge",[3]="Message acknowledged OK"}, 0x30)
pf_f_data_flags   = ProtoField.uint8("iop.flags.data_flags",  "Data Flags",    base.HEX,
    {[0]="Only data packet in single-packet stream",[1]="First data packet in multi-packet stream",
     [2]="Normal (middle) data packet",[3]="Last data packet in stream"}, 0xC0)

-- Shared address fields (subsystem is uint16!)
pf_src_subsystem_id = ProtoField.uint16("iop.src.subsystem", "Subsystem", base.DEC)
pf_src_node_id      = ProtoField.uint8 ("iop.src.node",      "Node",      base.DEC)
pf_src_component_id = ProtoField.uint8 ("iop.src.component", "Component", base.DEC)
pf_dst_subsystem_id = ProtoField.uint16("iop.dst.subsystem", "Subsystem", base.DEC)
pf_dst_node_id      = ProtoField.uint8 ("iop.dst.node",      "Node",      base.DEC)
pf_dst_component_id = ProtoField.uint8 ("iop.dst.component", "Component", base.DEC)

-- AS5669 (v1) specific fields
pf_v1_props      = ProtoField.uint8 ("iop.v1.properties",     "Properties",         base.HEX, nil, 0xFF)
pf_v1_priority   = ProtoField.uint8 ("iop.v1.priority",       "Priority",           base.DEC, nil, 0x0F)
pf_v1_acknak     = ProtoField.uint8 ("iop.v1.acknak",         "AckNak",             base.HEX,
    {[0]="No response required",[1]="Response required",
     [2]="Negative acknowledge",[3]="Acknowledged OK"}, 0x30)
pf_v1_svc_conn   = ProtoField.uint8 ("iop.v1.svc_conn",       "Service Connection", base.HEX,
    {[0]="Not a service connection",[1]="Service connection"}, 0x40)
pf_v1_exp        = ProtoField.uint8 ("iop.v1.experimental",   "Experimental",       base.HEX,
    {[0]="Not experimental",[1]="Experimental"}, 0x80)
pf_v1_msg_code   = ProtoField.uint16("iop.v1.message_code",   "Message Code",       base.HEX)
pf_v1_data_ctrl  = ProtoField.uint16("iop.v1.data_ctrl",      "Data Control",       base.HEX, nil, 0xFFFF)
pf_v1_data_len   = ProtoField.uint16("iop.v1.data_len",       "Data Length",        base.DEC, nil, 0x0FFF)
pf_v1_data_flags = ProtoField.uint16("iop.v1.data_flags",     "Data Flags",         base.HEX,
    {[0]="Single packet",[1]="First packet",[2]="Middle packet",[3]="Last packet"}, 0xF000)
pf_v1_seq_nr     = ProtoField.uint16("iop.v1.seq_nr",         "Sequence Number",    base.DEC)

proto.fields = {
    pf_messageid, pf_message_name, pf_sub_messageid,
    pf_msg_type, pf_hc_flags, pf_flags,
    pf_f_priority, pf_f_bcast, pf_f_acknak, pf_f_data_flags,
    pf_src_subsystem_id, pf_src_node_id, pf_src_component_id,
    pf_dst_subsystem_id, pf_dst_node_id, pf_dst_component_id,
    pf_v1_props, pf_v1_priority, pf_v1_acknak, pf_v1_svc_conn, pf_v1_exp,
    pf_v1_msg_code, pf_v1_data_ctrl, pf_v1_data_len, pf_v1_data_flags, pf_v1_seq_nr,
}

messagetable = DissectorTable.new("iop.message_id", "IOP Message ID's", ftypes.UINT16, base.HEX)

local my_info = { version = "2.1.0", author = "Lukas Boes" }
set_plugin_info(my_info)

-- AS5669 transport control command codes (cmd_code 0x0001-0x0007)
local AS5669_CTRL_CMDS = {
    [0x0001] = "CONNECT",
    [0x0002] = "ACCEPT",
    [0x0003] = "CANCEL",
    [0x0004] = "DISCONNECT",
    [0x0005] = "CONNECTED",
    [0x0006] = "HOLDING_RESPONSE",
    [0x0007] = "NOT_AUTHORIZED",
}

function bitstr(value, bits_count)
    local t = {}
    local idx = 0
    for i = 1, bits_count do
        local rest = value % 2
        table.insert(t, 1, rest)
        idx = idx + 1
        if idx == 4 then
            idx = 0
            table.insert(t, 1, ' ')
        end
        value = (value - rest) / 2
    end
    return table.concat(t)
end

function bitstr_part(value, bits_count, start_pos, end_pos)
    local t = {}
    local idx = 0
    for i = 1, bits_count do
        local rest = value % 2
        if start_pos <= idx and idx <= end_pos then
            table.insert(t, 1, rest)
        else
            table.insert(t, 1, '.')
        end
        idx = idx + 1
        if idx % 4 == 0 then
            table.insert(t, 1, ' ')
        end
        value = (value - rest) / 2
    end
    return table.concat(t)
end

function bitAND(value, bit_pos)
    local rest = 0
    for i = 0, bit_pos do
        rest = value % 2
        value = (value - rest) / 2
    end
    return rest
end

function bitVal(value, bit_start_pos, bit_end_pos)
    local t = {}
    for i = 1, bit_start_pos do
        local rest = value % 2
        value = (value - rest) / 2
    end
    for i = bit_start_pos, bit_end_pos do
        local rest = value % 2
        table.insert(t, 1, rest)
        value = (value - rest) / 2
    end
    return tonumber(table.concat(t), 2)
end


-- Dissector entry point
-- ─────────────────────────────────────────────────────────────────────────────
-- AS5669 (v1) full packet layout (offsets from byte 0 incl. transport version):
--
--   byte  0     : transport version (= 1)
--   bytes 1-2   : header compression flags (LE uint16, always 0x0000)
--   bytes 3-4   : total packet size in bytes  (BIG-ENDIAN uint16, min. 20)
--   byte  5     : properties = priority[3:0] | acknak[5:4] | svc_conn[6] | experimental[7]
--   byte  6     : JAUS protocol version (always 2)
--   bytes 7-8   : command code / message ID   (LE uint16)
--   bytes 9-12  : destination ID              (LE uint32): component[7:0]|node[15:8]|subsystem[31:16]
--   bytes 13-16 : source ID                   (LE uint32): same layout
--   bytes 17-18 : data control = data_len[11:0] | data_flags[15:12]  (LE uint16)
--   bytes 19-20 : sequence number             (LE uint16)
--   bytes 21+   : payload
--
-- AS5669A (v2) full packet layout (offsets from byte 0):
--   byte  0     : transport version (= 2)
--   byte  1     : msg_type[5:0] | hc_flags[7:6]
--   bytes 2-3   : data size (LE uint16, min. 14)
--   byte  4     : flags = priority[1:0] | bcast[3:2] | acknak[5:4] | data_flags[7:6]
--   bytes 5-8   : destination ID (LE uint32): same layout as v1
--   bytes 9-12  : source ID      (LE uint32): same layout as v1
--   bytes 13-14 : JAUS message ID + start of payload
--   last 2 bytes: sequence number (footer)
-- ─────────────────────────────────────────────────────────────────────────────
function proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = proto.name

    local subtree = tree:add(proto, buffer(), "IOP")
    local version = buffer(0, 1):le_uint()

    if version == 1 then
        -- ── AS5669 (version 1) ──────────────────────────────────────────────
        subtree:add_le(buffer(0, 1), "Version: 1 (AS5669)")

        -- minimum size: 1(ver)+2(hdr_compress)+2(total_size)+16(jaus_header) = 21 bytes
        if length < 21 then
            subtree:add_le(buffer(0, length), "[Packet too short for AS5669 header, need 21 bytes]")
            return
        end

        -- bytes 1-2: header compression (LE uint16, always 0)
        subtree:add_le(buffer(1, 2),
            string.format("Header Compression: 0x%04X", buffer(1, 2):le_uint()))

        -- bytes 3-4: total packet size (BIG-ENDIAN uint16)
        subtree:add(buffer(3, 2),
            string.format("Total Packet Size: %d", buffer(3, 2):uint()))

        -- byte 5: properties flags
        local v1_props_tree = subtree:add(pf_v1_props, buffer(5, 1))
        v1_props_tree:add(pf_v1_priority, buffer(5, 1))
        v1_props_tree:add(pf_v1_acknak,   buffer(5, 1))
        v1_props_tree:add(pf_v1_svc_conn, buffer(5, 1))
        v1_props_tree:add(pf_v1_exp,      buffer(5, 1))

        -- byte 6: JAUS protocol version (always 2)
        subtree:add(buffer(6, 1),
            string.format("JAUS Protocol Version: %d", buffer(6, 1):uint()))

        -- bytes 7-8: command code / message ID (LE uint16)
        local msg_code = buffer(7, 2):le_uint()

        -- bytes 9-12: destination ID (LE uint32)
        local dst_comp = buffer(9,  1):uint()
        local dst_node = buffer(10, 1):uint()
        local dst_sub  = buffer(11, 2):le_uint()
        dst_id = string.format("%d.%d.%d", dst_sub, dst_node, dst_comp)

        -- bytes 13-16: source ID (LE uint32)
        local src_comp = buffer(13, 1):uint()
        local src_node = buffer(14, 1):uint()
        local src_sub  = buffer(15, 2):le_uint()
        src_id = string.format("%d.%d.%d", src_sub, src_node, src_comp)

        subtree:append_text(string.format(", Src: %s, Dst: %s", src_id, dst_id))

        local dst_tree = subtree:add(buffer(9, 4),
            string.format("Destination ID: %s-%d", dst_id, buffer(9, 4):le_uint()))
        dst_tree:add_le(pf_dst_subsystem_id, buffer(11, 2))
        dst_tree:add(pf_dst_node_id,         buffer(10, 1))
        dst_tree:add(pf_dst_component_id,    buffer(9,  1))

        local src_tree = subtree:add(buffer(13, 4),
            string.format("Source ID: %s-%d", src_id, buffer(13, 4):le_uint()))
        src_tree:add_le(pf_src_subsystem_id, buffer(15, 2))
        src_tree:add(pf_src_node_id,         buffer(14, 1))
        src_tree:add(pf_src_component_id,    buffer(13, 1))

        -- bytes 17-18: data control (LE uint16)
        local data_ctrl_tree = subtree:add_le(pf_v1_data_ctrl, buffer(17, 2))
        data_ctrl_tree:add_le(pf_v1_data_len,   buffer(17, 2))
        data_ctrl_tree:add_le(pf_v1_data_flags, buffer(17, 2))

        -- bytes 19-20: sequence number (LE uint16)
        local seq_nr = buffer(19, 2):le_uint()
        subtree:add_le(pf_v1_seq_nr, buffer(19, 2))

        -- check for transport control commands (cmd_code 0x0001-0x0007)
        local cmd_name = AS5669_CTRL_CMDS[msg_code]
        if cmd_name ~= nil then
            subtree:add_le(buffer(7, 2),
                string.format("Command Code: 0x%04X (%s)", msg_code, cmd_name))
            subtree:append_text(string.format(", [%s]", cmd_name))
            pinfo.cols.info:set(string.format(
                "[%s] %s->%s, SeqNr: %d", cmd_name, src_id, dst_id, seq_nr))
        else
            -- regular JAUS application message; payload starts at byte 21
            subtree:add_le(pf_v1_msg_code, buffer(7, 2))
            pinfo.cols.info:set(string.format(
                "0x%04X, %s->%s, SeqNr: %d", msg_code, src_id, dst_id, seq_nr))

            if length > 21 then
                local packet_dissector = messagetable:get_dissector(msg_code)
                if packet_dissector ~= nil then
                    packet_dissector(buffer(21, length - 21):tvb(), pinfo, tree)
                    pinfo.cols.info:set(string.format(
                        "%s, %s->%s, SeqNr: %d",
                        tostring(pinfo.cols.info), src_id, dst_id, seq_nr))
                end
            end
        end

    else
        -- ── AS5669A (version 2 or unknown) ──────────────────────────────────
        subtree:add_le(buffer(0, 1),
            string.format("Version: %d (AS5669A)", version))

        local hc_flag = bitVal(buffer(1, 1):le_uint(), 6, 7)
        subtree:add(pf_msg_type, buffer(1, 1))
        subtree:add(pf_hc_flags, buffer(1, 1))

        if hc_flag == 0 then
            local payloadsize = buffer(2, 2):le_uint()
            subtree:add_le(buffer(2, 2), "Data Size: " .. payloadsize)

            local PDFlagsSubtree = subtree:add(pf_flags, buffer(4, 1))
            PDFlagsSubtree:add(pf_f_priority,   buffer(4, 1))
            PDFlagsSubtree:add(pf_f_bcast,      buffer(4, 1))
            PDFlagsSubtree:add(pf_f_acknak,     buffer(4, 1))
            PDFlagsSubtree:add(pf_f_data_flags, buffer(4, 1))

            src_id = string.format("%d.%d.%d",
                buffer(11, 2):le_uint(), buffer(10, 1):uint(), buffer(9, 1):uint())
            dst_id = string.format("%d.%d.%d",
                buffer(7,  2):le_uint(), buffer(6,  1):uint(), buffer(5, 1):uint())
            subtree:append_text(string.format(", Src: %s, Dst: %s", src_id, dst_id))

            local dst_id_subtree = subtree:add(buffer(5, 4),
                string.format("Destination ID: %s-%d", dst_id, buffer(5, 4):le_uint()))
            dst_id_subtree:add_le(pf_dst_subsystem_id, buffer(7, 2))
            dst_id_subtree:add(pf_dst_node_id,         buffer(6, 1))
            dst_id_subtree:add(pf_dst_component_id,    buffer(5, 1))

            local src_id_subtree = subtree:add(buffer(9, 4),
                string.format("Source ID: %s-%d", src_id, buffer(9, 4):le_uint()))
            src_id_subtree:add_le(pf_src_subsystem_id, buffer(11, 2))
            src_id_subtree:add(pf_src_node_id,         buffer(10, 1))
            src_id_subtree:add(pf_src_component_id,    buffer(9,  1))

            local seq_nr = buffer(length - 2, 2):le_uint()
            subtree:add_le(buffer(length - 2, 2), "Sequence Number: " .. seq_nr)

            local flags_val = buffer(4, 1):le_uint()
            local messageid = 0

            if bitAND(flags_val, 7) == 1 and bitAND(flags_val, 6) == 0 then
                local id_str = "Middle Data Packet"
                subtree:append_text(string.format(", %s", id_str))
                pinfo.cols.info:set(string.format(
                    "[middle] %s->%s, SeqNr: %d", src_id, dst_id, seq_nr))

            elseif bitAND(flags_val, 7) == 1 and bitAND(flags_val, 6) == 1 then
                local id_str = "Last Data Packet"
                subtree:append_text(string.format(", %s", id_str))
                pinfo.cols.info:set(string.format(
                    "[last] %s->%s, SeqNr: %d", src_id, dst_id, seq_nr))

            else
                if length - 1 >= 16 then
                    messageid = buffer(13, 2):le_uint()
                end
                subtree:add(pf_messageid, buffer(13, 2), messageid,
                    string.format("Message ID: 0x%04X", messageid))

                if bitAND(flags_val, 7) == 0 and bitAND(flags_val, 6) == 1 then
                    pinfo.cols.info:set(string.format("0x%04X [first]", messageid))
                else
                    pinfo.cols.info:set(string.format("0x%04X", messageid))
                end

                local packet_dissector = messagetable:get_dissector(messageid)
                if packet_dissector ~= nil then
                    packet_dissector(buffer(13, length - 15):tvb(), pinfo, tree)
                end
                pinfo.cols.info:set(string.format(
                    "%s, %s->%s, SeqNr: %d",
                    tostring(pinfo.cols.info), src_id, dst_id, seq_nr))
            end
        else
            -- handle compression
        end
    end
end


local udp_port = DissectorTable.get("udp.port")
udp_port:add(3794, proto)
udp_port:add(55555, proto)
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(3794, proto)

-- ############################
-- Generated Message Dissectors
-- ############################
