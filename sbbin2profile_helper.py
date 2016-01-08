import struct
import pprint


filter_dic = {
'0x1':'literal or subpath',
'0x3':'xattr',
'0x4':'file-mode',
'0x5':'ipc-posix-name',
'0x6':'global-name',
'0x7':'local-name',
'0x8':'local',
'0x9':'remote',
'0xa':'control-name',
'0xb':'socket-domain',
'0xc':'socket-type',
'0xd':'socket-protocol',
'0xe':'target',
<<<<<<< HEAD
'0xf':'fsctl-command',
=======
'0xf':'fsctl-command'
>>>>>>> 2fba56946526d44da3d34a5a820896f7e34d0f6d
'0x11':'iokit-user-client-class',
'0x12':'iokit-property',
'0x13':'iokit-connection',
'0x14':'device-major',
'0x15':'device-minor',
'0x16':'device-conforms-to',
'0x17':'extension',
'0x18':'extension-class',
'0x19':'appleevent-destination',
'0x1b':'right-name',
'0x1c':'preference-domain',
'0x1d':'vnode-type',
'0x1e':'entitlement',
'0x20':'Bundle ID',
'0x21':'kext-bundle-id',
'0x22':'info-type',
'0x23':'notification-name',
'0x24':'notification-payload',
<<<<<<< HEAD
'0x26':'sysctl-name',
'0x27':'process-name',
=======
'0x26':'sysctl-name'
'0x27':'process-name'
>>>>>>> 2fba56946526d44da3d34a5a820896f7e34d0f6d
'0x81':'regex',
'0x82':'mount-relative-regex',
'0x83':'xattr-regex',
'0x85':'ipc-posix-name-regex',
'0x86':'global-name-regex',
'0x87':'local-name-regex',
'0x91':'iokit-user-client-class-regex',
'0x92':'iokit-property-regex',
'0x9b':'right-name-regex',
'0xa0':'unknown 0xa0',
'0xa6':'sysctl-name-regex',
'0xa7':'process-name-regex'
}

#normal means the bytes behind filter indicate the offset of filter string. e.g:liteal
filter_type_normal = [ '0x1' ,'0x3' ,'0x5' ,'0x6','0x7', '0x8', '0x9', '0xa' ,'0x11', '0x12', '0x13' ,'0x17' ,'0x18','0x19' ,'0x1c', '0x1b','0x1e' ,'0x20','0x21' ,'0x22']

filter_type_regex = ['0x81', '0x82' ,'0x83', '0x85', '0x86', '0x87', '0x91', '0x9b']



#--------------------------------------------------------------------------------------#
#
#                                Parse Normal Filter
#
#
#--------------------------------------------------------------------------------------#


def parsefilter_for_normal(f,key,offset): #some like literal filter
    f.seek(offset * 8)
    filterByteCount = ord(f.read(1))
    f.read(3) #padding
    filterStr = '('

    if key == '0x1': #distinguish literal and subpath
        stamp = ord(f.read(1))
        filterStr += "literal" if stamp ==0x0 else "subpath"
    else:
        filterStr += filter_dic[key]
    filterStr += "\"%s\"" % f.read(filterByteCount)
    filterStr += ')\n'
    return filterStr

def getfilterStr(f,offset,regex_table_offset):
    filterStr = ''
    f.seek(offset * 8)
    f.read(1) #0x00 indicate filter
    filter, filter_arg, match, unmatch = struct.unpack('<BHHH', f.read(7)) #filter_arg is filter string offset for normal filter ;offset in regex_table for regex
    key = str(hex(filter))
    
    if key in filter_type_normal:
        filterStr = filterStr + "   " +parsefilter_for_normal(f,key,filter_arg)
    elif filter == 0x04:
        filterStr +='\t(file-mode  #o'
        f.seek(offset *8 + 2)
        bitString = bin(int(struct.unpack('<H',f.read(2))[0]))[2:]
        bitString = bitString.rjust(12,'0')
        print bitString
        print '%d' % int(bitString[0:3],2)
        stickBit = int(bitString[0:3],2)
        userBit = int(bitString[3:6],2)
        groupBit = int(bitString[6:9],2)
        otherBit = int(bitString[9:12],2)
        filterStr += "%d%d%d%d" % (stickBit,userBit,groupBit,otherBit)
        filterStr +=')\n'
        #print filterStr


    elif filter == 0x0b or filter == 0x0c or filter == 0x0d:
<<<<<<< HEAD
        filterStr += '\t'+filter_dic[str(hex(filter))]
=======
        filterStr += '\t'+filter_dic[filter]
>>>>>>> 2fba56946526d44da3d34a5a820896f7e34d0f6d
        f.seek(offset *8 + 2)
        domaintype = struct.unpack('<H',f.read(2))[0]
        socketfilterStr = ''
        """
        if domaintype == 0x11:
            socketfilterStr = 'AF_ROUTE'
        elif domaintype == 0x20:
            socketfilterStr = 'AF_SYSTEM'
        else:
            socketfilterStr = 'unknown domain type'
        """
<<<<<<< HEAD
        filterStr =filterStr + "   " +str(hex(domaintype))+')\n'
=======
        filterStr =filterStr + "   " +domaintype+')\n'
>>>>>>> 2fba56946526d44da3d34a5a820896f7e34d0f6d
   
    elif filter == 0x0f:
        filterStr += '\t(fsctl-command '
        f.seek(offset *8 + 2)
        number = int(ord(f.read(1)))
        ch = f.read(1)
        fsctlfilterStr = '(_IO "%s",%d)' % (ch,number)
        filterStr =filterStr + "   " +fsctlfilterStr+')\n'
    elif filter == 0x0e:
        filterStr += '\t(target '
        f.seek(offset *8 + 2)
        targettype = struct.unpack('<H',f.read(2))[0]
        targetfilterStr = ''
        if targettype == 0x01:
            targetfilterStr = 'self'
        elif targettype == 0x02:
            targetfilterStr = 'groups'
        elif targettype == 0x03:
            targetfilterStr = 'others'
        else:
            targetfilterStr = 'unknown domain type'
        filterStr =filterStr + "   " +targetfilterStr+')\n'


    elif filter == 0x1d:
        filterStr += '\t(vnode-type'
        f.seek(offset *8 + 2)
        vnodetype = struct.unpack('<H',f.read(2))[0]
        vnodefilterStr = ''
        if vnodetype == 0x01:
            vnodefilterStr = 'REGULAR-FILE'
        elif vnodetype == 0x02:
            vnodefilterStr = 'DIRECTORY'
        elif vnodetype == 0x05:
            vnodefilterStr = 'SYMLINK'
        elif vnodetype == 0xffff:
            vnodefilterStr = 'TTY'
        else:
            vnodefilterStr = 'unknown vnode type'
        filterStr =filterStr + "   " +vnodefilterStr+')\n'
     
    elif key in filter_type_regex:
        filterStr += parse_reg_expr(f,key,regex_table_offset,filter_arg)
        #filterStr += '")\n'
    else:
        filterStr += '\tunknown(%s)\n' % key

    #print filterStr
    return filterStr



#--------------------------------------------------------------------------------------#
#
#                                Parse Regex Expression
#
#
#--------------------------------------------------------------------------------------#

def parse_reg_expr(f,key,regex_table_offset,offset_in_regexTable):
    resultstr = '\t(%s #"' % filter_dic[key]
    f.seek(regex_table_offset * 8 + offset_in_regexTable *2)
    re_expr_offset =  struct.unpack('<H',f.read(2))[0]
    f.seek(re_expr_offset * 8)
    re_expr_bytecount = ord(f.read(1))
    f.read(3) #padding
    f.read(4) #unknown
    f.read(2) #rest reg_expr_bytecount
    parse_flag = 0
    while True:
        readbyte = f.read(1)
        if not readbyte:
            break
        byte = struct.unpack('<B', readbyte)[0]
        #print chr(byte)
        if not byte:
            break;
        if parse_flag:
            resultstr += chr(byte)
            parse_flag = 0;
        elif byte == 0x2f:
            resultstr += parse_reg_meta_expr(f)
        elif byte == 0x09:
            resultstr += '.'            
        elif byte == 0x19:
            resultstr += '^'
        elif byte == 0x29:
            resultstr += '$'
        elif byte == 0x02:
            parse_flag = 1
        elif byte % 16 == 0xb:
            f.seek(f.tell()-1)
            resultstr += parse_reg_square_bracket(f)
            #print 'square bracket'
        elif byte == 0x15:
            break        
    resultstr += '")\n'
    return resultstr


def parse_reg_meta_expr(f):
    parse_reg_flag = 0
    reg_expr_str = ''
    f.read(2) #unknown
    while True:
        byte = struct.unpack('<B', f.read(1))[0]
        if parse_reg_flag:
            reg_expr_str += chr(byte)
            parse_reg_flag = 0
        elif byte == 0x0a:
            f.read(2)
            reg_expr_str += '*'
            break
        elif byte == 0x02:
            parse_reg_flag = 1
        elif byte == 0x09:
            reg_expr_str += '.'            
        elif byte == 0x19:
            reg_expr_str += '^'
        elif byte == 0x29:
            reg_expr_str += '$'
        elif byte == 0x2f:
            reg_expr_str += parse_reg_meta_expr(f)
        elif byte % 16 == 0xb:
            #print 'square bracket'
            f.seek(f.tell()-1)
            reg_expr_str += parse_reg_square_bracket(f)
        elif byte == 0x15:
            f.seek(f.tell()-1)
            break
    return reg_expr_str

def parse_reg_square_bracket(f): #parse somelike [0-9]
    byte = struct.unpack('<B', f.read(1))[0]
    expr_count = (byte / 16 ) * 2
    resultstr = '['
    bracket_flag = 0
    preByte = None

    if expr_count == 0:
        bracket_flag = 1
    while True:
        byte = struct.unpack('<B', f.read(1))[0]
        if not bracket_flag:
            if expr_count == 0:
                f.seek(f.tell()-1)
                break
            expr_count -= 1
        if byte == 0x02:
            byte = struct.unpack('<B', f.read(1))[0]
            resultstr += chr(byte)
            if byte == 0x5d and bracket_flag:
                break
        else:
            if not preByte:
                preByte = byte
            else:
                if byte == preByte:
                    resultstr += str(byte)
                    preByte = None
                else:
                    resultstr += chr(preByte) + '-' + chr(byte)
    if not bracket_flag:
        resultstr +=']'
    return resultstr


#--------------------------------------------------------------------------------------#
#
#                                Others Fun
#
#--------------------------------------------------------------------------------------#


def get_nettype(type):
    if type == 0x0b:
        return 'udp'
    elif type == 0x07:
        return 'tcp'
    elif type == 0x03:
        return 'ip'
    else:
        return 'unknown net type'


def load_op_names_ios(ops_count): 
    f = open('ops.txt', 'r')
    ops = [s.strip() for s in f.readlines()]
    return ops[0:ops_count]

