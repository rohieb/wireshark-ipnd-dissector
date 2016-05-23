-- Wireshark Dissector for the IP Neighbor Discovery protocol
-- as specified in https://tools.ietf.org/html/draft-irtf-dtnrg-ipnd-00 et seq.
--
-- Copyright (c) Roland Hieber <rohieb@rohieb.name>
-- All rights reserved.
-- 
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions
-- are met:
-- 
-- 1. Redistributions of source code must retain the above copyright
--    notice, this list of conditions and the following disclaimer.
-- 2. Redistributions in binary form must reproduce the above copyright
--    notice, this list of conditions and the following disclaimer in the
--    documentation and/or other materials provided with the distribution.
-- 
-- THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
-- ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-- IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-- ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
-- FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
-- DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
-- OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
-- HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
-- LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
-- OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
-- SUCH DAMAGE.
--

--local bit  = require("bit")

ipnd = Proto("ipnd", "IP Neighbor Discovery")

--
-- Error handling
--

local ef_unknown_version = ProtoExpert.new("ipnd.err.unknown_version", "Unknown Version",
	expert.group.UNDECODED, expert.severity.WARN)
local ef_sdnv_malformed = ProtoExpert.new("ipnd.err.sdnv_malformed", "Malformed SDNV",
	expert.group.MALFORMED, expert.severity.ERROR)
local ef_too_short = ProtoExpert.new("ipnd.err.too_short", "Insufficient bytes remaining in packet",
	expert.group.MALFORMED, expert.severity.ERROR)

ipnd.experts = { ef_unknown_version, ef_sdnv_malformed, ef_too_short }

--
-- Protocol Fields
--

local pf_version           = ProtoField.uint8 ("ipnd.version"          , "Version")
local pf_flags             = ProtoField.new   ("Flags", "ipnd.flags", ftypes.UINT8, nil, base.HEX)
local pf_beacon_len        = ProtoField.bytes ("ipnd.beacon_length"    , "Beacon Length")
local pf_seqno             = ProtoField.uint16("ipnd.seqno"            , "Sequence Number")
local pf_eid               = ProtoField.string("ipnd.eid"              , "Canonical EID")
local pf_service_name      = ProtoField.bytes ("ipnd.service_name"     , "Service Name")
local pf_service_param     = ProtoField.bytes ("ipnd.service_param"    , "Service Parameter")

local    flag_v1_zerolength_mask = 0x01
local pf_flag_v1_zerolength = ProtoField.bool("ipnd.flags.zero_length",
	"Zero Length", 8, {"yes","no"}, flag_v1_zerolength_mask, "no Length or EID fields present")
local    flag_v2_has_eid_mask = 0x01
local pf_flag_v2_has_eid = ProtoField.bool("ipnd.flags.has_eid",
	"EID Present", 8, {"yes","no"}, flag_v2_has_eid_mask, "EID and EID Length fields are present")
local    flag_v2_has_svb_mask = 0x02
local pf_flag_v2_has_svb = ProtoField.bool("ipnd.flags.has_service_block",
	"Service Block present", 8, {"yes","no"}, flag_v2_has_svb_mask)
local    flag_v2_has_nbf_mask = 0x04
local pf_flag_v2_has_nbf = ProtoField.bool("ipnd.flags.has_nbf",
	"Neighborhood Bloom Filter present", 8, {"yes","no"}, flag_v2_has_nbf_mask)

ipnd.fields = {
	pf_version, pf_flags, pf_beacon_len, pf_seqno, pf_eid_len, pf_eid,
	pf_service_name, pf_service_param,
	pf_flag_v1_zerolength, pf_flag_v2_has_eid, pf_flag_v2_has_svb, pf_flag_v2_has_nbf, 
}

--
-- Primitive decoding functions
--

-- Decode SDNV value
-- @returns (value, length) of SDNV, or (nil, ef_error) in case of error.
local function sdnv_decode(buffer)
	if buffer:len() == 0 then
		return nil, ef_too_short
	end

	local value = 0
	local value_len = 0
	local bytes = buffer:bytes()

	repeat
		if value_len >= buffer:len() then
			return nil, ef_sdnv_malformed
		end

		local b = bytes:get_index(value_len)
		value = bit.bor(bit.lshift(value, 7), bit.band(b, 0x7f))
		value_len = value_len + 1

	until bit.band(b, 0x80) == 0

	return value, value_len
end

-- Decode string prefixed with SDNV length.
-- @returns (len, len_len, string), or (nil, ef_error) in case of error
local function sdnv_string_decode(buffer)
	if buffer:len() == 0 then
		return nil, ef_too_short
	end

	local len, len_len = sdnv_decode(buffer)
	local str, str_len = "", 0

	if not len then
		return nil, len_len -- len_len is the ef_error value
	elseif len and len > buffer:len() then
		return nil, ef_too_short
	elseif len and len > 0 then
		return len, len_len, buffer:range(len_len, len):string()
	else -- len == 0
		return len, len_len, ""
	end
end

-- parse and add a SDNV-prefixed string to a tree
-- calls cb_filter(len, len_len, str) which can do error checking and return nil/(ef_error, string)
-- @returns (len, len_len, str) or nil in case of error
local function tree_add_sdnv_string(tree, buffer, name, pf_string, cb_filter)
	local len, len_len, str = sdnv_string_decode(buffer)

	if len and len > buffer:len() then
		len, len_len = nil, ef_too_short
	elseif len and cb_filter then
		local ef_error, ef_string = cb_filter(len, len_len, str)
		if ef_error then
			len, len_len, str = nil, ef_error, ef_string
		end
	end

	if not len then
		local subtree = tree:add(buffer, name .. ": [error]")
		subtree:add_proto_expert_info(len_len)
		return nil
	else
		local subtree = tree:add(buffer(0, len+len_len), name .. ": " .. str)
		subtree:add(buffer(0, len_len), "String Length: " .. len)
		subtree:add(pf_string, buffer(len_len, len), "String Value: " .. str)
		return len, len_len, str
	end
end

-- parse a v1 service block and add entries to the tree
local function v1_service_block_decode(tree, buffer)
	local len, len_len, str, tmplen

	local subtree = tree:add(buffer, "Service: ")
	
	len, len_len, str = tree_add_sdnv_string(subtree, buffer, "Service Name", pf_service_name,
		function(len, _, __)
			if len == 0 then return ef_too_short, "Service Name has length 0" end
		end)
	if not len then
		return nil
	end
	tmplen = len + len_len

	subtree:set_len(tmplen)
	subtree:append_text(str .. ", params: ")

	len, len_len, str = tree_add_sdnv_string(subtree, buffer(tmplen), "Service Parameters",
		pf_service_name, function(len, _, __)
			if len == 0 then return ef_too_short, "Service Parameter string has length 0" end
		end)
	if not len then
		return nil
	end

	subtree:set_len(tmplen + len + len_len)
	subtree:append_text(str)

	return tmplen + len + len_len
end

--
-- High-level dissectors per IPND version
--

-- IPND version 1, see https://tools.ietf.org/html/draft-irtf-dtnrg-ipnd-00
local function dissect_ipnd_v1(buffer, pinfo, tree)
	-- FIXME
end

-- IPND version 2, see https://tools.ietf.org/html/draft-irtf-dtnrg-ipnd-01
local function dissect_ipnd_v2(buffer, pinfo, tree)
	-- Flags
	-- _,value = add_packet_field(...) does not work for bitfields, use bitop and flag masks manually.
	-- see https://github.com/wireshark/wireshark/blob/master/epan/wslua/wslua_tree.c#L136
	local flag_range = buffer:range(1,1)
	local flag_tree = tree:add(pf_flags, flag_range)
	flag_tree:add(pf_flag_v2_has_eid, flag_range)
	flag_tree:add(pf_flag_v2_has_svb, flag_range)
	flag_tree:add(pf_flag_v2_has_nbf, flag_range)

	local flag_has_eid = (bit.band(flag_range:uint(), flag_v2_has_eid_mask) ~= 0)
	local flag_has_svb = (bit.band(flag_range:uint(), flag_v2_has_svb_mask) ~= 0)
	local flag_has_nbf = (bit.band(flag_range:uint(), flag_v2_has_nbf_mask) ~= 0)

	-- Sequence Number
	tree:add(pf_seqno, buffer:range(2,2))

	local offset = 4
	
	-- EID
	if flag_has_eid then
		local len, len_len = tree_add_sdnv_string(tree, buffer(offset), "EID", pf_eid)
		if not len then
			return nil
		end
		offset = offset + len + len_len
	end

	-- Service Block
	if flag_has_svb then
		local num, len = sdnv_decode(buffer:range(offset))
		if num then
			tree:add(buffer(offset, len), "Number of Service Block entries: " .. num)
			offset = offset + len

			-- iterate over entries
			local n = 0
			while (n < num) do
				len = v1_service_block_decode(tree, buffer:range(offset))
				if not len then
					return nil
				end
				offset = offset + len
				n = n + 1
			end
		else
			local subtree = tree:add(buffer(offset), "Number of Service Block entries: [error]")
			subtree:add_proto_expert_info(len)
			return nil
		end

	end -- if flag_has_svb

	-- Neighborhood Bloom Filter
	if flag_has_nbf then
		-- FIXME: we have no testdata for this...
	end
end

-- IPND version 3, see https://tools.ietf.org/html/draft-irtf-dtnrg-ipnd-03
local function dissect_ipnd_v3(buffer, pinfo, tree)
end

local version_dissectors = {
	[1] = dissect_ipnd_v1,
	[2] = dissect_ipnd_v2,
	[3] = dissect_ipnd_v3,
}

--
-- Dissector scaffolding
--
function ipnd.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = "IPND"
	local subtree = tree:add(ipnd, buffer(0), "IP Neighbor Discovery")
	local version_range = buffer:range(0,1)
	local version = version_range:uint()

	subtree:add(pf_version, version_range)
	
	if version_dissectors[version] then
		version_dissectors[version](buffer, pinfo, subtree)
	else
		subtree:add_proto_expert_info(ef_unknown_version)
	end
end

--
-- Dissector registration for UDP port 4551
--
udp_table = DissectorTable.get("udp.port")
udp_table:add(4551, ipnd)
