import sys
import struct
import pprint
from sbbin2profile_helper import *


OPS_COUNT = 0x72


gFilterStr = ''

def parse_decision_graph(f,ops_offset,index,isYesBranch,regex_table_offset):#index means the count of tap
    global gFilterStr
    f.seek(8 * ops_offset)
    is_result = ord(f.read(1)) == 1

    if is_result:
        #global filterResult
        f.read(1) #padding
        isAllowed = ord(f.read(1)) == 0
        str = ''
        if isAllowed:
            str = 'allow'
        else:
            str = 'deny'
        #filterResult += '\t\t\t'+'\t'*index+str+'\n'
        gFilterStr += '\t\t'+'\t'*index+str+'\n'
    else:   
        gFilterStr += '\t\t'+'\t'*index+'if'+getfilterStr(f,ops_offset,regex_table_offset)
        #filterResult += '\t\t'+'\t'*index+'if'+getfilterStr(f,offset)
        f.seek(ops_offset * 8)
        f.read(1) #padding
        filter, filter_arg, match, unmatch = struct.unpack('<BHHH', f.read(7))
        parse_decision_graph(f,match,index+1,1,regex_table_offset)
        if not isYesBranch:
            parse_decision_graph(f,unmatch,0,0,regex_table_offset)
        


def parse_filter(f,ops_offset,regex_table_offset):
    f.seek(8 * ops_offset)
    is_result = ord(f.read(1)) == 1
    if is_result:
        f.read(1) #padding
        resultCode = ord(f.read(1))
        resultStr = {0:'allow',5:'deny'}[resultCode]
        return (True,resultStr)
    else:
        global gFilterStr
        gFilterStr = ''
        parse_decision_graph(f,ops_offset,0,0,regex_table_offset,)
        return (False,gFilterStr)



with open(sys.argv[1],'rb') as f:
    ops = load_op_names_ios(OPS_COUNT)

    f.seek(2) #unknown bytes ,seem to 0 now
    regex_table_offset,regex_table_count = struct.unpack('<HH',f.read(4))
    ops_table = struct.unpack('<%dH' % OPS_COUNT,f.read(2 * OPS_COUNT))
    ops_bag = []



    for i,ops_offset in enumerate(ops_table):
        if i == 0:
            default_ops_offset = ops_offset
        if ops_offset not in ops_bag:
            ops_bag.append(ops_offset)
            filter = parse_filter(f,ops_offset,regex_table_offset)
            if filter[0]: #result
                if i == 0:
                    default_op = filter[1]
                print '(%s %s)' % (filter[1] ,ops[i])
            else:
                print '(%s %s \n' % ('deny' if default_op == 'allow' else 'allow',ops[i])
                print filter[1] 

    



