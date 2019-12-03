 #!/usr/intel/bin/python

import sys, getopt
import json_parsing_lib

json_file = ''

def process_args(argv):
    global json_file
    global json_name
    global copyright_message_file
    try:
        opts, args = getopt.getopt(argv,"hj:",["jfile="])
    except getopt.GetoptError:
        print ("Usage - python parse_json_cmd.py -j <json input file> ")
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ("Usage - python parse_json_cmd.py -j <json input file> ")
            sys.exit()
        elif opt in ("-j", "--jfile"):
            json_file = arg

    if (json_file == ''):
        print ("Error, json input file must be specified")
        sys.exit(2)
    else:
        print ("Json input file is ", json_file)

def parse_json_file(json_file):
    global ctx
    global ht
    global ph
    global hs
    global ps
    global pls 
    global ac
    global pt

    ctx = json_parsing_lib.json_context(json_file)
    ht = json_parsing_lib.header_types_extractor(ctx)
    ph = json_parsing_lib.packet_headers_extractor(ctx)
    hs = json_parsing_lib.header_stacks_extractor(ctx)
    ps = json_parsing_lib.parser_states_extractor(ctx)
    ac = json_parsing_lib.action_info_extractor(ctx)
    pls = json_parsing_lib.pipeline_info_extractor(ctx)
    pt = json_parsing_lib.parse_graph_generator(ctx)
    #pt.print_parse_graph(ctx)
 
 
def print_json_file_p4_16():
    global ctx
    global ht
    global ph
    global hs
    global ps
    global pls
    global ac

    ht.printall(ctx)
    ph.printall(ctx)
    hs.printall(ctx)
    ps.printall(ctx)
    ac.printall(ctx)
    pls.printall(ctx)
 
def print_count():
    global ctx
    global ht
    global ph
    global hs
    global ps
    global pls
    global ac   
    
   
    print ("Header Types Count = " + str(ht.count(ctx)))
    print ("Packet Header Count = " + str(ph.count(ctx)))
    print ("Header Stack Count = " + str(hs.count(ctx)))
    print ("Parser State Count = " + str(ps.count(ctx)))
    print ("Action Entries Count = " + str(ac.count(ctx)))
    print ("Pipeline Stages Count = " + str(pls.count(ctx)))
    print ("\n")

def print_all_iter():
    global ctx
    global ht
    global ph
    global hs
    global ps
    global pls
    global ac
 

    for i in range (ht.count(ctx)):
        ht.printone(ht.next(ctx))

    if (ph.count(ctx) > 0):
        ph.printheader(ctx)
        for i in range (ph.count(ctx)):
            ph.printone(ph.next(ctx))
        ph.printfooter()
        
    for i in range (hs.count(ctx)):
        hs.printone(hs.next(ctx))

    if (ps.count(ctx) > 0):
        ps.printheader(ctx)
        for i in range (ps.count(ctx)):
            ps.printone(ps.next(ctx), ctx)
        ps.printfooter()
   
def main(argv):
    global json_file

    process_args(argv)

    # Always call this first to extract all headers
    parse_json_file(json_file)
  
    # test code to print count 
    # print_count() 

    # use 'print_all_iter' or 'print_json_file_p4_16' to print all headers
    print ("//program name = " + ctx.program_name)

    #print_all_iter()

    print_json_file_p4_16()


if __name__ == "__main__":
    main(sys.argv[1:])

