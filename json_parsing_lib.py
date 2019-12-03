import json
import math
import re
import os.path

class json_context:
    input_file = ''
    json_name = ''
    json_ext = ''
    copyright_message_file = ''
    output_file = ''
    program_name = ''
    json_data = {}
    p4_data = {}
    p4_header_list = {}
    p4_packet_structure_list = {}
    p4_header_stack_list = {}
    p4_parser_state_list = {}
    p4_pipeline_list = {}
    p4_action_list = {}
    p4_params = {}
    p4_parse_tree = {}
    p4_header_enums = {} 
    def __init__(self, json_file):
        self.json_data = open(json_file)
        self.p4_data = json.load(self.json_data)
        self.program_name = self.p4_data.get("program", None)

class header_field:
    def __init__(self, header_field_name_p, header_field_width_p):
        self.header_field_name = header_field_name_p
        self.header_field_width = header_field_width_p
        self.p4_header_list = {}

class p4_header:
    def __init__(self, header_name_p):
        self.header_name = header_name_p
        self.header_field_count = 0
        self.header_field_list = {}

class packet_structure_member:
    def __init__(self, packet_structure_member_p, packet_structure_type_p, packet_structure_metadata_type_p):
        self.packet_structure_member_name = packet_structure_member_p
        self.packet_structure_member_type = packet_structure_type_p
        self.packet_structure_member_metadata_type = packet_structure_metadata_type_p

class p4_packet_structure:
    def __init__(self, packet_structure_name_p):
        self.packet_structure_name = packet_structure_name_p
        self.packet_structure_member_count = 0
        self.packet_structure_member_list = {}

class header_stacks_entry:
    def __init__(self, header_stacks_entry_name_p, header_stacks_entry_type_p, header_stacks_entry_size_p):
        self.header_stacks_entry_name = header_stacks_entry_name_p
        self.header_stacks_entry_size = header_stacks_entry_size_p
        self.header_stacks_entry_type = header_stacks_entry_type_p

class header_stack_list:
    def __init__(self):
        self.header_stacks_member_count = 0
        self.header_stacks_member_list = {}


class action_runtime_data:
    def __init__(self, action_runtime_data_name_p, action_runtime_data_bitwidth_p):
        self.action_runtime_data_name = action_runtime_data_name_p
        self.action_runtime_data_bitwidth = action_runtime_data_bitwidth_p

class action_primitives_parameters:
    def __init__(self, primitives_parameter_type_p, primitives_parameter_value_p):
        self.primitives_parameter_type = primitives_parameter_type_p
        self.primitives_parameter_value = primitives_parameter_value_p

class action_primitives:
    def __init__(self, primitive_ops_p):
        self.primitives_ops = primitive_ops_p
        self.primitives_parameters_list = {}

class action_entry:
    def __init__(self, action_name_p, action_id_p):
        self.action_name = action_name_p
        self.action_id = action_id_p
        self.action_runtime_data_list = {}
        self.action_primitives_list = {}
 
class parser_state_ops:
    def __init__(self, parser_op_type_p, parser_op_value_p):
        self.parser_op_type = parser_op_type_p
        self.parser_op_value = parser_op_value_p

class parser_transition_state:
    def __init__(self, transition_state_value_p, transition_mask_value_p, transition_next_state_value_p):
        self.transition_state_value = transition_state_value_p
        self.transition_mask_value = transition_mask_value_p
        self.transition_next_state_value = transition_next_state_value_p

class parser_transition_key_values:
    def __init__(self, parser_transition_key_p):
        self.parser_transition_key = parser_transition_key_p
        self.parser_transition_next_state_count = 0
        self.parser_transition_next_state_list = {}

class parser_state_entry:
    def __init__(self, parser_name_p, protocol_name_p):
        self.parser_name = parser_name_p
        self.protocol_name = protocol_name_p
        self.parser_ops_count = 0
        self.parser_transition_key_count = 0
        self.parser_ops_list = {}
        self.transition_key_value_list = {}

class pipeline_key_info:
    def __init__(self, match_type_p, target_0_p, target_1_p, mask_p):
        self.match_type = match_type_p
        self.target_0 = target_0_p
        self.target_1 = target_1_p
        self.mask = mask_p

class pipeline_table_info:
    def __init__(self, table_name_p, table_id_p):
        self.pipeline_table_name = table_name_p
        self.pipeline_table_id = table_id_p
        self.pipeline_key_list = {}

class pipeline_info:
    def __init__(self, pipeline_name_p, pipeline_id_p, pipeline_init_table_p):
        self.pipeline_stage_name = pipeline_name_p
        self.pipeline_stage_id = pipeline_id_p
        self.pipeline_stage_init_table = pipeline_init_table_p
        self.pipeline_stage_tables_list = {}

class parse_tree_node:
    def __init__(self):
        self.transition_state_count = 0
        self.sublevel = {}

class sublevel_node:
    def __init__(self, parent_name_p):
        self.parent_name = parent_name_p
        self.level_name = None
        self.field=[0 for i in range(3)]
        self.mask=[0 for i in range(3)]
        self.tree_node = None
    def update_value(self, index, field_val, mask_val):
        self.field[index] = field_val
        self.mask[index] = mask_val
    def print_body(self):
        print ("Address = %s" %self)
        print ("Parent name = %s" %self.parent_name)
        print ("Level name = %s" %self.level_name)
        for k in range(3):
            print ("Field[%d] = %x, Mask[%d] = %x" %(k, self.field[k], k, self.mask[k]))

   
class header_types_extractor:
    
    def __init__(self, ctx):
        self.curr = 0
        i = 0
        for header_types in ctx.p4_data.get("header_types"):
            self.__extract(header_types, i, ctx)
            i = i+1

    def __extract(self, header_types, ndx, ctx):
        header_name = header_types.get("name", None)
        ctx.p4_header_list[ndx] = p4_header(header_name)
        i = 0
        for header_fields in header_types.get("fields", None):
            j = len(header_fields)
            if ((j!=2) and (j!=3)):
                print ("Error, fields must be a 2-element or a 3-element tuple")
                sys.exit(2)
            ctx.p4_header_list[ndx].header_field_list[i] = header_field(header_fields[0], header_fields[1])
            i = i+1
        ctx.p4_header_list[ndx].header_field_count = i

    def __iter__(self):
        return self

    def next(self, ctx):
        if (self.curr < len(ctx.p4_header_list)):
            self.curr += 1
            return ctx.p4_header_list[self.curr - 1]
        else:
            self.curr = 0
            StopIteration()
 
    def count(self, ctx):
        return len(ctx.p4_header_list)

    def printone(self, p4_header_list_in):
        print ("header %s {" % p4_header_list_in.header_name)
        for j in range (p4_header_list_in.header_field_count):
            print ("    bit<%s> %s;" % (p4_header_list_in.header_field_list[j].header_field_width, \
                                      p4_header_list_in.header_field_list[j].header_field_name))
        print("}")

    def printall(self, ctx):
        for ndx in range (len(ctx.p4_header_list)):
            self.printone(ctx.p4_header_list[ndx])

class packet_headers_extractor:

    def __init__(self, ctx):
        self.curr = 0
        ctx.p4_packet_structure_list = p4_packet_structure("packet_t")
        i = 0
        for this_hdr in ctx.p4_data.get("headers"):
            self.__extract(this_hdr, i, ctx)
            i = i+1
        ctx.p4_packet_structure_list.packet_member_count = i

    def __extract(self, this_hdr, ndx, ctx):
   
        str_name = this_hdr.get("name", None)
        str_type = this_hdr.get("header_type", None)
        metadata_type = this_hdr.get("metadata", False)
        ctx.p4_packet_structure_list.packet_structure_member_list[ndx] = packet_structure_member(str_name, str_type, metadata_type)

    def __iter__(self):
        return self

    def next(self, ctx):
        if (self.curr < ctx.p4_packet_structure_list.packet_member_count):
            self.curr += 1
            return ctx.p4_packet_structure_list.packet_structure_member_list[self.curr - 1]
        else:
            self.curr = 0
            StopIteration()

    def count(self, ctx):
        return ctx.p4_packet_structure_list.packet_member_count

    def printheader(self, ctx):
        print ("struct %s {" % ctx.p4_packet_structure_list.packet_structure_name)

    def printone(self, pkt_in):
        if (pkt_in.packet_structure_member_metadata_type != True):
            print ("    @name(\"%s\")" % pkt_in.packet_structure_member_name)
            print ("    %s    %s;" %(pkt_in.packet_structure_member_type,
                                      pkt_in.packet_structure_member_name))

    def printfooter(self):
        print ("}")

    def printall(self, ctx):
        self.printheader(ctx)
        for i in range(ctx.p4_packet_structure_list.packet_member_count):
            self.printone(ctx.p4_packet_structure_list.packet_structure_member_list[i])
        self.printfooter()

class header_stacks_extractor:

    def __init__(self, ctx):
        self.curr = 0
        ctx.p4_header_stack_list = header_stack_list()
        i = 0
        for header_stacks in ctx.p4_data.get("header_stacks", None):
            self.__extract_header_stacks(header_stacks, i, ctx)
            i = i+1
        ctx.p4_header_stack_list.header_stacks_member_count = i

    def __extract_header_stacks(self, this_hdr, ndx, ctx):
        str_name = this_hdr.get("name", None)
        str_type = this_hdr.get("header_type", None)
        str_size = len(this_hdr.get("header_ids", None))
        metadata_type = this_hdr.get("metadata", False)
        if (metadata_type != True):
            ctx.p4_header_stack_list.header_stacks_member_list[ndx] = header_stacks_entry(str_name, str_type, str_size)

    def __iter__(self):
        return self

    def next(self, ctx):
        if (self.curr < ctx.p4_header_stack_list):
            self.curr += 1
            return ctx.p4_header_stack_list.header_stacks_member_list[self.curr - 1]
        else:
            self.curr = 0
            StopIteration()

    def count(self, ctx):
        return ctx.p4_header_stack_list.header_stacks_member_count

    def printone(self, stack_in):
        print ("%s    %s[%d];" %(stack_in.header_stacks_entry_name, \
                                    stack_in.header_stacks_entry_type, \
                                    stack_in.header_stacks_entry_size))   

    def printall(self, ctx):
        for i in range(ctx.p4_header_stack_list.header_stacks_member_count):
            self.printone(ctx.p4_header_stack_list.header_stacks_member_list[i])

class parser_states_extractor:

    def __init__(self, ctx):
        self.curr = 0
        i = 0
        for parsers in ctx.p4_data.get("parsers"):
            for parser_states in parsers.get("parse_states", None):
                self.__extract_parser_states(parser_states, i, ctx)
                i = i+1

    def __extract_parser_states(self, this_hdr, ndx, ctx):
        parser_name = this_hdr.get("name", None)
        uppercase_name = parser_name.upper()
        #uppercase_name = parser_name
        protocol_name = uppercase_name.replace("PARSE_", "")
        ctx.p4_parser_state_list[ndx] = parser_state_entry(parser_name, protocol_name)
        i = 0
        for parser_ops in this_hdr.get("parser_ops", None):
            parser_parameters = parser_ops.get("parameters", None)
            parser_op_value = parser_parameters[0].get("value", None)
            parser_op_type = parser_ops.get("op", None)
            if ((parser_op_type != None) and (parser_op_value != None)):
                ctx.p4_parser_state_list[ndx].parser_ops_list[i] = parser_state_ops(parser_op_type, parser_op_value)
            i = i+1
        ctx.p4_parser_state_list[ndx].parser_ops_count = i
        
        transition_key = this_hdr.get("transition_key", None)
        tlen = len(transition_key)
        if (tlen == 0):
            transitions = this_hdr.get("transitions", None)
            tvalue0 = transitions[0].get("value", None)
            tvalue1 = transitions[0].get("mask", None)
            tvalue2 = transitions[0].get("next_state", None)
            ctx.p4_parser_state_list[ndx].parser_transition_key_count = 0
            ctx.p4_parser_state_list[ndx].parser_transition_key_value_list = parser_transition_key_values(None)
            ctx.p4_parser_state_list[ndx].parser_transition_key_value_list.next_state_count = 1
            ctx.p4_parser_state_list[ndx].parser_transition_key_value_list.parser_transition_next_state_list[0] = \
                parser_transition_state(tvalue0, tvalue1, tvalue2)
        else:
            select_name = {}
            ctx.p4_parser_state_list[ndx].parser_transition_key_count = tlen
            for i in range(tlen):
                tvalue = transition_key[i].get("value", None)
                value1 = tvalue[0]
                value2 = tvalue[1]    
                select_name[i] = "hdr."+value1+"."+value2
                ctx.p4_parser_state_list[ndx].parser_transition_key_value_list = parser_transition_key_values(select_name)
                j = 0
                for transitions in this_hdr.get("transitions", None):
                    tvalue0 = transitions.get("value", None)
                    tvalue1 = transitions.get("mask", None)
                    tvalue2 = transitions.get("next_state", None)
                    ctx.p4_parser_state_list[ndx].parser_transition_key_value_list.parser_transition_next_state_list[j] = \
                        parser_transition_state(tvalue0, tvalue1, tvalue2)
                    j = j+1
                ctx.p4_parser_state_list[ndx].parser_transition_key_value_list.next_state_count = j

    def __iter__(self):
        return self

    def next(self, ctx):
        if (self.curr < len(ctx.p4_parser_state_list)):
            self.curr += 1
            return ctx.p4_parser_state_list[self.curr - 1]
        else:
            self.curr = 0
            StopIteration()

    def count(self, ctx):
        return len(ctx.p4_parser_state_list)

    def printheader(self, ctx):
        if (len(ctx.p4_parser_state_list) > 0):
            print ("\nparser ParserImpl(packet_in packet, out packet_t hdr, inout metadata M, inout standard_metadata_t standard_metdadata) {")
 
    def printone(self, state_in, ctx):
        print ("    @protocol_id(\"%s\") @name (\"%s\") state %s {" %(state_in.protocol_name, \
                                                                 state_in.parser_name.upper(), \
                                                                 state_in.parser_name)) 
        if (state_in.parser_ops_count == 0):
            print ("        transition accept;")
            print ("    }")
            return
        
        for i in range(state_in.parser_ops_count):
            print ("        packet.%s(hdr.%s)" %(state_in.parser_ops_list[i].parser_op_type, \
                                            state_in.parser_ops_list[i].parser_op_value))
        if (state_in.parser_transition_key_count == 0):
            tvalue0 = state_in.parser_transition_key_value_list.parser_transition_next_state_list[0].transition_state_value
            tvalue1 = state_in.parser_transition_key_value_list.parser_transition_next_state_list[0].transition_mask_value
            tvalue2 = state_in.parser_transition_key_value_list.parser_transition_next_state_list[0].transition_next_state_value
            if (tvalue0 == "default"):
                if (tvalue2 != None):
                    print ("        transition %s;" %tvalue2)
                else:
                    print ("        return accept;")
        else:
            print ("        transition select (", end='')
            for i in range(state_in.parser_transition_key_count):
                 if (i != 0):
                     print(", ", end='')
                 print ("%s" % state_in.parser_transition_key_value_list.parser_transition_key[i], end='')
            print (") {")
            for i in range(len(state_in.parser_transition_key_value_list.parser_transition_next_state_list)):
                 tvalue0 = state_in.parser_transition_key_value_list.parser_transition_next_state_list[i].transition_state_value
                 tvalue1 = state_in.parser_transition_key_value_list.parser_transition_next_state_list[i].transition_mask_value
                 tvalue2 = state_in.parser_transition_key_value_list.parser_transition_next_state_list[i].transition_next_state_value
                 if tvalue2 is None:
                     tvalue2 = "accept"
                 if (state_in.parser_transition_key_count == 1):
                     if (tvalue0 != "default"):
                         hex_tvalue0 = int(tvalue0, 16)
                         if (hex_tvalue0 > 255):
                             print ("            16w%s : %s;" %(tvalue0, tvalue2))
                         else:
                             print ("            8w%s : %s;" %(tvalue0, tvalue2))
                     else:
                         print ("            %s : accept;" %tvalue0)
                 else:
                     if (tvalue0 != "default"):
                         k = 2
                         print ("            ", end = '')
                         for j in range(state_in.parser_transition_key_count):
                             tvalue_j = tvalue0[k:k+4]
                             hex_tvalue0 = int(tvalue_j, 16)
                             if (j != 0):
                                 print(", ", end = '')
                             print ("16w0x%s " %tvalue_j, end = '')
                             k+=4
                         print (": %s;" %tvalue2)
                     else:
                          print ("            %s : accept;" %tvalue0)
                            
            print ("        }")
            print ("    }")

    def printfooter(self):
        print ("}")


    def printall(self, ctx):
        self.printheader(ctx)
        for ndx in range(len(ctx.p4_parser_state_list)):
           self.printone(ctx.p4_parser_state_list[ndx], ctx)
        self.printfooter()


class parse_graph_generator:

    def __init__(self, ctx):
        curr = 0
        start_state = None
        start_state_name = None
        self.max_level = 0
        self.max_transition = 0
        start_state, start_state_name = self.find_start_state(ctx, "start")
        if (start_state_name != None):
            print("Start state for parse graph = %s" %start_state_name)
        else:
            print("Error, can not generate parse graph")
        for i in range(16):
            ctx.p4_parse_tree[i] = None
        ctx.p4_parse_tree[0] = parse_tree_node() 
        self.create_parse_tree(ctx.p4_parse_tree[0], start_state, start_state_name, ctx, curr)

    def find_start_state(self, ctx, state_name):
        start_state = None
        start_state_name = None
        for ndx in range(len(ctx.p4_parser_state_list)):
            state_in = ctx.p4_parser_state_list[ndx]
            if (state_in.parser_name == state_name):
                if (state_in.parser_transition_key_count == 0):
                    tvalue2 = state_in.parser_transition_key_value_list.parser_transition_next_state_list[0].transition_next_state_value
                    if (tvalue2 != None):
                        start_state, start_state_name = self.find_parser_state(ctx, tvalue2)
                        
        return start_state, start_state_name
 

    def find_parser_state(self, ctx, state_name):
        start_state = None
        start_state_name = None
        for ndx in range(len(ctx.p4_parser_state_list)):
            state_in = ctx.p4_parser_state_list[ndx]
            if (state_in.parser_name == state_name):
                return state_in, state_in.parser_name
        return None, None
 
    def create_parse_tree(self, p4_node_p, state_in, start_state_name, ctx, cur_level):
        p4_node = p4_node_p
        if (cur_level > self.max_level):
            self.max_level = cur_level

        tree_node_name = None
        header_field_name = None
        next_state_name = None
        next_state = None
        if (state_in.parser_ops_count > 0) :
            header_field_name = state_in.parser_ops_list[0].parser_op_value
            if (header_field_name == "ethernet"):
                tree_node_name = "ethernet_e"
            if (header_field_name == "ethernet[0]"):
                tree_node_name = "ethernet_0_e"
            if (header_field_name == "ethernet[1]"):
                tree_node_name = "ethernet_1_e"
            if (header_field_name == "ipv4"):
                tree_node_name = "ipv4_e"
            if (header_field_name == "ipv4[0]"):
                tree_node_name = "ipv4_0_e"
            if (header_field_name == "ipv4[1]"):
                tree_node_name = "ipv4_1_e"
            if (header_field_name == "ipv6"):
                tree_node_name = "ipv6_e"
            if (header_field_name == "ipv6[0]"):
                tree_node_name = "ipv6_0_e"
            if (header_field_name == "ipv6[1]"):
                tree_node_name = "ipv6_1_e"
            if (header_field_name == "udp"):
                tree_node_name = "udp_e"
            if (header_field_name == "udp[0]"):
                tree_node_name = "udp_0_e"
            if (header_field_name == "udp[1]"):
                tree_node_name = "udp_1_e"
            if (header_field_name == "tcp"):
                tree_node_name = "tcp_e"
            if (header_field_name == "tcp[0]"):
                tree_node_name = "tcp_0_e"
            if (header_field_name == "tcp[1]"):
                tree_node_name = "tcp_1_e"
            if (header_field_name == "vxlan"):
                tree_node_name = "vxlan_e"
            if (header_field_name == "gtpu"):
                tree_node_name = "gtpu_e"
            ii = len(ctx.p4_header_enums)
            found = False
            for i in range(ii):
                if (ctx.p4_header_enums[i] == tree_node_name):
                    found = True
                    return
            if (not found):
                ctx.p4_header_enums[ii] = tree_node_name
        #else:
            #print("Escape path")
            #print ("parser_name = %s" %state_in.parser_name)

        begin_index = p4_node.transition_state_count
        this_node_index_count = len(state_in.parser_transition_key_value_list.parser_transition_next_state_list)
        if ((begin_index + this_node_index_count) > self.max_transition):
            self.max_transition = begin_index + this_node_index_count
        p4_node.transition_state_count += this_node_index_count
 
        if (state_in.parser_transition_key_count == 0):
            tvalue0 = state_in.parser_transition_key_value_list.parser_transition_next_state_list[0].transition_state_value
            tvalue1 = state_in.parser_transition_key_value_list.parser_transition_next_state_list[0].transition_mask_value
            tvalue2 = state_in.parser_transition_key_value_list.parser_transition_next_state_list[0].transition_next_state_value
            #print ("tree_node_name = %s" %tree_node_name)
            #print ("begin_index = %d" %begin_index)
            #print ("tvalue0 = %s" %tvalue0)
            #print ("tvalue1 = %s" %tvalue1)
            #print ("tvalue2 = %s" %tvalue2)
            p4_node.sublevel[begin_index] = sublevel_node(tree_node_name)
            if (tvalue0 == "default"):
                if (tvalue2 != None):
                    next_state, next_state_name = self.find_parser_state(ctx, tvalue2)
                    if (next_state_name != None):
                        p4_node.sublevel[begin_index].level_name = tvalue2
                        if (ctx.p4_parse_tree[cur_level+1] == None):
                            ctx.p4_parse_tree[cur_level+1] = parse_tree_node()
                        self.create_parse_tree(ctx.p4_parse_tree[cur_level+1], next_state, next_state_name, ctx, cur_level+1)
                else:
                    return
        else:
            for ndx in range(this_node_index_count):
                tvalue0 = state_in.parser_transition_key_value_list.parser_transition_next_state_list[ndx].transition_state_value
                tvalue1 = state_in.parser_transition_key_value_list.parser_transition_next_state_list[ndx].transition_mask_value
                tvalue2 = state_in.parser_transition_key_value_list.parser_transition_next_state_list[ndx].transition_next_state_value
                p4_node.sublevel[begin_index+ndx] = sublevel_node(tree_node_name)
                if tvalue2 is None:
                    tvalue2 = "accept"
                if (state_in.parser_transition_key_count == 1):
                    if (tvalue0 != "default"):
                        hex_tvalue0 = int(tvalue0, 16)
                        p4_node.sublevel[ndx].field[0] = hex_tvalue0
                        hex_mvalue0 = 0xffff
                        p4_node.sublevel[begin_index+ndx].update_value (0, hex_tvalue0, hex_mvalue0)
                else:
                    if (tvalue0 != "default"):
                        k = 2
                        for j in range(state_in.parser_transition_key_count):
                             tvalue_j = tvalue0[k:k+4]
                             hex_tvalue0 = int("0x"+tvalue_j, 16)
                             hex_mvalue0 = 0xffff
                             p4_node.sublevel[begin_index+ndx].update_value(j, hex_tvalue0, hex_mvalue0)
                             k+=4
                p4_node.sublevel[begin_index+ndx].level_name = tvalue2
                next_state, next_state_name = self.find_parser_state(ctx, tvalue2)
                if (next_state_name != None):
                     if (ctx.p4_parse_tree[cur_level+1] == None):
                         ctx.p4_parse_tree[cur_level+1] = parse_tree_node()
                     self.create_parse_tree(ctx.p4_parse_tree[cur_level+1], next_state, next_state_name, ctx, cur_level+1)
            


            return

    def print_parse_graph(self, ctx):
        print ("****** Parse Graph ****")
        print ("Max level = %d" %self.max_level)
        print ("Max transitions = %d" %self.max_transition)
        self.print_tree(ctx.p4_parse_tree[0], 0)

    def print_tree(self, p4_node, node_level ):
        print ("Node at level %d" %(node_level))
        for j in range (p4_node.transition_state_count):
            print ("Sublevel %d, address %s --- " %(j,p4_node.sublevel[j]))
            p4_node.sublevel[j].print_body()
            if (p4_node.sublevel[j].tree_node != None):
                self.print_tree(p4_node.sublevel[j].tree_node, node_level+1)

 


 

class pipeline_info_extractor:
    curr = 0
    
    def __init__(self, ctx):
        self.curr = 0
        i = 0
        for pipeline_types in ctx.p4_data.get("pipelines"):
            self.__extract(pipeline_types, i, ctx)
            i = i+1

    def __extract(self, pipeline_types, ndx, ctx):
        pipeline_name = pipeline_types.get("name", None)
        pipeline_id = pipeline_types.get("id", 0)
        pipeline_init_table = pipeline_types.get("init_table", None)
        ctx.p4_pipeline_list[ndx] = pipeline_info(pipeline_name, pipeline_id, pipeline_init_table)
        i = 0
        for tables in pipeline_types.get("tables", None):
            table_name = tables.get("name", None)
            table_id = tables.get("id", 0)
            ctx.p4_pipeline_list[ndx].pipeline_stage_tables_list[i] = pipeline_table_info(table_name, table_id)
            j = 0
            for keys in tables.get("key", None):
                key_match_type = keys.get("match_type", None)
                key_target = keys.get("target", None)
                key_mask = keys.get("mask", None)
                if (len(key_target) == 2):
                    key_target_0 = key_target[0]
                    key_target_1 = key_target[1]
                else:
                    key_target_0 = key_target
                    key_target_1 = None
                ctx.p4_pipeline_list[ndx].pipeline_stage_tables_list[i].pipeline_key_list[j] = pipeline_key_info(key_match_type, key_target_0, key_target_1, key_mask)
                j = j + 1
            i = i + 1
 

    def __iter__(self):
        return self

 
    def next(self, ctx):
        if (self.curr < len(ctx.p4_pipeline_list)):
            self.curr += 1
            return ctx.p4_pipeline_list[self.curr - 1]
        else:
            self.curr = 0
            StopIteration()
 
    def count(self, ctx):
        return len(ctx.p4_pipeline_list)

    def printone(self, p4_pipeline_list_in):
        print ("pipeline %s {" % p4_pipeline_list_in.pipeline_stage_name)
        for j in range (len(p4_pipeline_list_in.pipeline_stage_tables_list)):
            print ("    table  %s {" % p4_pipeline_list_in.pipeline_stage_tables_list[j].pipeline_table_name)
            print ("        key = ")
            for k in range(len(p4_pipeline_list_in.pipeline_stage_tables_list[j].pipeline_key_list)):
                print ("            hdr.%s.%s : %s" % (p4_pipeline_list_in.pipeline_stage_tables_list[j].pipeline_key_list[k].target_0, \
                                                     p4_pipeline_list_in.pipeline_stage_tables_list[j].pipeline_key_list[k].target_1,
                                                   p4_pipeline_list_in.pipeline_stage_tables_list[j].pipeline_key_list[k].match_type))
            print ("    }")
        print ("}")

    def printall(self, ctx):
        for ndx in range (len(ctx.p4_pipeline_list)):
            self.printone(ctx.p4_pipeline_list[ndx])

class action_info_extractor:
    curr = 0
    
    def __init__(self, ctx):
        self.curr = 0
        i = 0
        for action_types in ctx.p4_data.get("actions"):
            self.__extract(action_types, i, ctx)
            i = i+1

    def __extract(self, action_types, ndx, ctx):
        action_name = action_types.get("name", None)
        action_id = action_types.get("id", 0)
        ctx.p4_action_list[ndx] = action_entry(action_name, action_id)
        i = 0
        for runtime_data in action_types.get("runtime_data", None):
            runtime_data_name = runtime_data.get("name", None)
            runtime_data_bitwidth = runtime_data.get("bitwidth", 0)
            ctx.p4_action_list[ndx].action_runtime_data_list[i] = action_runtime_data(runtime_data_name, runtime_data_bitwidth)
            i = i + 1
        j = 0
        for primitives in action_types.get("primitives", None):
            primitives_ops = primitives.get("op", None)
            ctx.p4_action_list[ndx].action_primitives_list[j] = action_primitives(primitives_ops)
            k = 0
            for parameters in primitives.get("parameters", None):
                parameters_type = parameters.get("type", None)
                parameters_value = parameters.get("value", None)
                if (type(parameters_value) == type(1)):
                    tmp = parameters_value
                    paramters_value = str(tmp)
                else:
                    if  (len(parameters_value) == 2):
                        tmp = parameters_value
                        parameters_value = tmp[0]+"."+tmp[1]
                ctx.p4_action_list[ndx].action_primitives_list[j].primitives_parameters_list[k] = action_primitives_parameters(parameters_type, parameters_value)
                k = k + 1
            j = j + 1

    def __iter__(self):
        return self

 
    def next(self, ctx):
        if (self.curr < len(ctx.p4_action_list)):
            self.curr += 1
            return ctx.p4_action_list[self.curr - 1]
        else:
            self.curr = 0
            StopIteration()
 
    def count(self, ctx):
        return len(ctx.p4_action_list)

    def printone(self, p4_action_list_in):
        print ("@name (\"%s\") action %s (" % (p4_action_list_in.action_name, p4_action_list_in.action_name))
        #print ("    runtime_data {")
        for i in range(len(p4_action_list_in.action_runtime_data_list)):
            print ("        bit<%s> %s" % (p4_action_list_in.action_runtime_data_list[i].action_runtime_data_bitwidth, p4_action_list_in.action_runtime_data_list[i].action_runtime_data_name))
        print ("    )")
        print ("    {")
        for j in range (len(p4_action_list_in.action_primitives_list)):
            primitive_ops = p4_action_list_in.action_primitives_list[j].primitives_ops
            for k in range (0,len(p4_action_list_in.action_primitives_list[j].primitives_parameters_list),2):
                ops_field_type = p4_action_list_in.action_primitives_list[j].primitives_parameters_list[k].primitives_parameter_type
                ops_field_value = p4_action_list_in.action_primitives_list[j].primitives_parameters_list[k].primitives_parameter_value
                ops_value_type = p4_action_list_in.action_primitives_list[j].primitives_parameters_list[k+1].primitives_parameter_type
                ops_value_string = p4_action_list_in.action_primitives_list[j].primitives_parameters_list[k+1].primitives_parameter_value
                #print ("ops_field_type = %s" %ops_field_type)
                #print ("ops_field_value = %s" %ops_field_value)
                #print ("ops_value_type = %s" %ops_value_type)
                #print ("ops_value_string = %s" %ops_value_string)
                #print ("primitive_ops = %s" %primitive_ops)
                if (primitive_ops == "assign"):
                    if ((ops_field_type == "field") and (ops_value_type == "hexstr")):
                        print("        %s = %s" %(ops_field_value, ops_value_string))
                    if ((ops_field_type == "field") and (ops_value_type == "runtime_data")):
                        indx = int(ops_value_string)
                        print("        %s = %s" %(ops_field_value, p4_action_list_in.action_runtime_data_list[indx].action_runtime_data_name))
                        
        print ("    }")

    def printall(self, ctx):
        for ndx in range (len(ctx.p4_action_list)):
            self.printone(ctx.p4_action_list[ndx])


