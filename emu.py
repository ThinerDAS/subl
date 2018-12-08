#!/usr/bin/python

import array
import os
#import random
#import time
"""The behavior between python and C version may not be the same all the time!"""


def btoi(b):
    return sum(b[i] << (i*8) for i in range(len(b)))


def get_subword(i, addr, n):
    addr = (addr & 3 & (-n))
    return (i >> (8*addr)) & ((1 << (8*n))-1)


def write_subword(new_i, old_word, addr, n):
    addr = (addr & 3 & (-n))
    mask = ((1 << (8*n))-1) << (8*addr)
    return (old_word & (~mask)) | ((new_i << (8*addr)) & mask)


class Environ(object):
    inv_list = [1,
                2863311531,
                3435973837,
                3067833783,
                954437177,
                3123612579,
                3303820997,
                4008636143,
                4042322161,
                678152731,
                1022611261,
                3921491879,
                3264175145,
                1749801491,
                1332920885,
                3186588639,
                1041204193,
                2331553675,
                2437684141,
                2532929431,
                3247414297,
                799063683,
                2767867813,
                1736263375,
                438261969,
                4210752251,
                2350076445,
                1483715975,
                3089362441,
                2693454067,
                3238827797,
                3204181951]

    def __init__(self, memory, flag):
        self.memory = [None]*(2**10)
        self.rMEMSTAT = 0
        rand_chr = self.randint() & 0xff
        for i in range((len(memory)+1023)//1024):
            self.rMEMSTAT += 1
            l = list(memory[i*1024:(i+1)*1024])
            if len(l) < 1024:
                l += [0]*(1024-len(l))
            self.memory[2**9+rand_chr+i] = array.array('I', l)
        f = flag[:79]+'\0'
        f += os.urandom(80-len(f))
        self.rsFLAG = array.array('I')
        self.rsFLAG.fromlist(
            [btoi(bytearray(f[i*4:(i+1)*4])) for i in range(20)])
        self.rsFLAG_key = 0
        self.rPC = 0x200000 | (rand_chr << 12)
        self.rCYCLE = 0
        self.rJCYCLE = 0
        # notice that all our code are inside binary, so we cannot use too large binary
        # currently we are using 4M memory maximally
        # 2M low is uninitialized (zero), 2M high is code (though also writeable)
        # we may shrink further TODO since we may not need that much code/data, especially we do not need 2M code

    def run_forever(self):
        while True:
            self.step()

    def step(self):
        pc = self.rPC
        op_a = self.read_abs(pc & ((1 << 22)-1), 4)
        op_b = self.read_abs((pc+4) & ((1 << 22)-1), 4)
        orig_op_c = self.read_abs((pc+8) & ((1 << 22)-1), 4)
        self.rPC = (pc+12) & ((1 << 22)-1)
        n = [4, 4, 2, 1][orig_op_c & 3]
        op_c = orig_op_c & -4
        ph_a = self.address_translate(op_a)
        ph_b = self.address_translate(op_b)
        ph_c = self.address_translate(op_c)
        A = self.read_abs(ph_a, n, False)  # left is not forced
        B = self.read_abs(ph_b, n)  # right is forced
        self.write_abs(ph_a, n, (A-B) & ((1 << (8*n))-1))
        self.rCYCLE += 1
        if A < B and self.rPC != ph_c:
            #print 'op_c', hex(op_c), 'ph_c', hex(ph_c)
            self.rPC = ph_c
            self.rJCYCLE += 1

        self.on_step(pc, op_a, op_b, op_c, n, ph_a,
                     ph_b, ph_c, A, B, self.rPC)

    def read_dma(self, address, forced):
        assert address < 128
        i = address >> 2
        res = 0
        if i == 1:
            # pc
            res = self.rPC
        elif i == 4:
            # inst cycle
            res = self.rCYCLE
        elif i == 5:
            # io
            if 0 == (address & 3) and forced:
                res = self.getchar()
        elif i == 6:
            # rand
            res = self.randint()
        elif i == 7:
            # host time
            res = int(self.gettime()) % (2**32-1)
        elif i == 8:
            # jmp times
            res = self.rJCYCLE
        elif i == 9:
            # mem pages
            res = self.rMEMSTAT
        elif 12 <= i < 32:
            res = self.rsFLAG[i-12] ^ (self.rsFLAG_key*(i*2+1)) & 0xffffffff
        return res

    def write_dma(self, address, n, value):
        assert address < 128
        if address == 20:
            self.putchar(value & 0xff)
        elif address == 40:
            # 14, sleep, must be aligned write
            self.sleep(value)
        elif address == 44:
            # 15, halt, must be aligned write
            self.halt(value)
        elif address >= 48:
            # TODO test the logic here, whether a write seems to be normal
            orig = self.rsFLAG[(address >> 2)-12]
            v = write_subword(
                value, orig ^ (self.rsFLAG_key*((address >> 2)*2+1)) & 0xffffffff, address, n) ^ orig
            self.rsFLAG_key = (v * Environ.inv_list[address >> 2]) & 0xffffffff

    def read_abs(self, address, n, forced=True):
        """read absolute address"""
        # unless forced, IO register read as zero
        # n=1,2,4 indicate that read is 1byte, 2bytes, 4bytes
        if address < 128:
            res = self.read_dma(address, forced)
        else:
            idx = address >> 12
            off = (address >> 2) & ((1 << 10)-1)
            if self.memory[idx] is None:
                res = 0
            else:
                res = self.memory[idx][off]
        return get_subword(res, address, n)

    def write_abs(self, address, n, value):
        """write absolute address"""
        if address < 128:
            self.write_dma(address, n, value)
        else:
            idx = address >> 12
            off = (address >> 2) & ((1 << 10)-1)
            if self.memory[idx] is None:
                if value == 0:
                    return
                self.memory[idx] = array.array('I', [0]*1024)
                self.rMEMSTAT += 1
            self.memory[idx][off] = write_subword(
                value, self.memory[idx][off], address, n)

    def address_translate(self, address):
        addr_type = (address >> 22) & ((1 << 6)-1)
        base_addr = self.read_abs(addr_type << 2, 4, False)
        return (base_addr+address) & ((1 << 22)-1)

    def getchar(self):
        # return char as integer
        raise NotImplementedError(
            'One should subclass this class and provide a `getchar`')

    def putchar(self, c):
        raise NotImplementedError(
            'One should subclass this class and provide a `putchar`')

    def randint(self):
        raise NotImplementedError(
            'One should subclass this class and provide a `randint`')

    def gettime(self):
        raise NotImplementedError(
            'One should subclass this class and provide a `gettime`')

    def sleep(self, msec):
        raise NotImplementedError(
            'One should subclass this class and provide a `sleep`')

    def halt(self, code):
        raise NotImplementedError(
            'One should subclass this class and provide a `halt`')

    def on_step(self, inst_pc, inst_a, inst_b, inst_c, n, ph_a, ph_b, ph_c, mem_A, mem_B, next_pc):
        pass


import random
import time
import sys
import string


class NormalEnviron(Environ):
    def __init__(self, memory, flag, debug=False):
        super(NormalEnviron, self).__init__(memory, flag)
        self.debug = debug
        self.dbg_chr = False
        self.trace = []

    def getchar(self):
        self.flush_trace()
        v = ord(sys.stdin.read(1))
        if not self.debug and v == 0:
            self.debug = True
            return ord(sys.stdin.read(1))
        return v

    def putchar(self, c):
        cc = chr(c)
        # little hack for debug chars
        if self.dbg_chr:
            sys.stdout.write("\x1b[34;1m{:02x}\x1b[m".format(c))
            self.dbg_chr = False
            return
        if cc == '\x01':
            self.dbg_chr = True
            return
        # if cc not in string.printable and cc != '\x1b':
        # else:
        sys.stdout.write(cc)

    def randint(self):
        return random.randint(0, 2**32-1)

    def gettime(self):
        return int(time.time()) % (2**32)

    def sleep(self, msec):
        self.flush_trace()
        print >>sys.stderr, "(Sleep", msec, 'ms)'
        time.sleep(msec/1000.0)

    def halt(self, code):
        self.flush_trace()
        print >>sys.stderr, "Program exited with status", code
        exit(code)
        #raise Exception("Program exited with status ")

    def flush_trace(self):
        if not self.debug:
            return
        for tup in self.trace:
            n = tup[4]
            if n == 1:
                fmt = '{0:06x}: {1:08x} {2:08x} {3:08x}B\n{1:08x}({5:06x})={8:02x}------ {2:08x}({6:06x})={9:02x}------, {3:08x}({7:06x}), =>{10:06x}'
            elif n == 2:
                fmt = '{0:06x}: {1:08x} {2:08x} {3:08x}W\n{1:08x}({5:06x})={8:04x}---- {2:08x}({6:06x})={9:04x}----, {3:08x}({7:06x}), =>{10:06x}'
            elif n == 4:
                fmt = '{0:06x}: {1:08x} {2:08x} {3:08x}D\n{1:08x}({5:06x})={8:08x} {2:08x}({6:06x})={9:08x}, {3:08x}({7:06x}), =>{10:06x}'
            print >>sys.stderr, '\x1b[32;1m'+fmt.format(*tup)+'\x1b[m'
        print >>sys.stderr, '\x1b[33;1m==<end of fragment>==\x1b[m'
        self.trace = []

    def on_step(self, inst_pc, inst_a, inst_b, inst_c, n, ph_a, ph_b, ph_c, mem_A, mem_B, next_pc):
        if self.debug:
            self.trace.append((inst_pc, inst_a, inst_b, inst_c, n,
                               ph_a, ph_b, ph_c, mem_A, mem_B, next_pc))
            if next_pc != inst_pc+12:
                # print all traces and clean
                self.flush_trace()
            #print 'PC:', hex(self.rPC)
            #print 'AT0:', hex(self.read_abs((32+3)<<2, 4))
        if self.rPC < 0x200000:
            print 'crashed'
            self.halt(-2)
        if self.rCYCLE > 0x10000:
            print 'TLE'
            self.halt(-3)


def do_main(mem_filename, flag_filename):
    with open(mem_filename, 'rb') as f:
        raw = f.read()
    mem = array.array('I')
    mem.fromstring(raw)
    if flag_filename:
        with open(flag_filename, 'rb') as f:
            flag = f.read().strip()
    else:
        flag = ''
    NormalEnviron(mem, flag).run_forever()


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print >>sys.stderr, 'Usage:\n\t'+sys.argv[0]+' rom.bin [flag]'
        exit(-1)
    do_main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
