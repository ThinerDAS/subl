# SUBL

SUBL is one variant of [OISC](https://en.wikipedia.org/wiki/One_instruction_set_computer). Here, SUBL is an educational [instruction set architecture](https://en.wikipedia.org/wiki/Instruction_set_architecture) based on the single instruction: SUBL (subtract and branch if less than).

This architecture supports a special addressing mode, which is base address + offset. As PC is itself mapped into the address space, this architecture supports [PIC](https://en.wikipedia.org/wiki/Position-independent_code), enabling [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) to be implemented easily.

This architecture itself is far from realistic - each instruction is 12 bytes long, considering that one subl instruction can express very little information. Serious computer architecture scientists will not advocate for this architecture for obvious reasons.

This fictional architecture made her first appearance in a domestic CTF AWD competition as a pwnable, namely [XNUCA](http://xnuca.erangelab.com/). Only one team seems to manage to solve the challenge in the competition in the final hours ([Aurora](https://ctftime.org/team/23890)), and the team is not [0ops](https://ctftime.org/team/4419) as we expected. `simplenote.bin` is the pwnable rom.

This architecture shares the idea with the DEFCON CTF 2017 [Clemency](https://blog.legitbs.net/2017/07/the-clemency-architecture.html) architecture, different only in that `subl` architecture is very simple, reasonable for 2 days of implementation (mostly working compiler of it, for a `simplenote`). As for the competition, the reason why we used `subl` instead of the more famous `subleq`, is that we suspected that `subleq` decompiler exists on the Internet, considering that we are not the first to [employ esolang for a pwnable](https://legitbs.net/statdump_2017/challenges/9.html).

## Pwnable nature

As in `simplenote.bin`, ASLR is enabled. Stack and code addresses are randomized (though entropy is pretty low). Also a weak flag encryption scheme is enabled, so attacker should use [Known Plaintext Attack](https://en.wikipedia.org/wiki/Known-plaintext_attack) or reencrypt the flag with a [weak key](https://en.wikipedia.org/wiki/Weak_key) finally.

[NX](https://en.wikipedia.org/wiki/NX_bit) is not implemented here, as enabling NX will require some more modification of compiler, namely, we need to separate `.text`+`.rodata` and `.data`+`.bss` into different regions and have some controller DMA region about page protections. [Stack canary](https://en.wikipedia.org/wiki/Stack-Smashing_Protector#Canaries) is not implemented either, sadly.

As far as the author's knowledge, there are in total 7 vulnerabilities inside the `simplenote.bin`. The solver team probably employed around 2-3 of them.

## Usage

`subl` and `emu.py` are two implementations of this architecture.

`./subl simplenote.bin flag`

`./emu.py simplenote.bin flag`

There are certain differences between the two implementations. Also the `subl` here is a bit different from the binary in the competition. In the competition, the provided binary is unstripped and the SUBL binary is inside the ELF. Also the `subl` here fixed two bugs occurred in the binary distributed in the competition.

`subl` binary is merely for convenience. It is compiled within `alpine` docker statically, stripped.
