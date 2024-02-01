from binaryninja.log import log_info, log_warn
from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType

from .zeus import instructions, OperandRegisterLow, OperandRegisterHigh, OperandImmediate, OperandPC, OperandDP, OperandData

class Zeus(Architecture):
    name = 'zeus'

    address_size = 4
    default_int_size = 1
    instr_alignment = 1
    max_instr_length = 255

    # supress warning
    stack_pointer = "SP"

    opcode_xor_keys = {}

    def get_instruction_info(self, data, addr):
        result = InstructionInfo()

        opcode = data[0]
        inst_data = data
        if addr > 0:
            if addr not in self.opcode_xor_keys:
                log_warn("no opcode xor key at 0x%x" % (addr))
                return result
            else:
                opcode ^= self.opcode_xor_keys[addr]
                opcode &= 0x7f
                inst_data = bytes([opcode]) + data[1:]

        inst = instructions[opcode](inst_data)
        inst.parse(inst_data)

        result.length = inst.size
        self.opcode_xor_keys[addr + inst.size] = inst.key

        if inst.text == 'exit':
            result.add_branch(BranchType.FunctionReturn)
        elif inst.text.startswith('loop'):
            disp = inst.operands[1].value
            result.add_branch(BranchType.TrueBranch, addr + inst.size - disp)
            result.add_branch(BranchType.FalseBranch, addr + inst.size)

        return result

    def get_operand_tokens(self, operand):
        result = []
        if isinstance(operand, OperandRegisterLow) or isinstance(operand, OperandRegisterHigh):
            result.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, 'r%d' % operand.reg_index))
        elif isinstance(operand, OperandImmediate):
            result.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, '0x%x' % operand.value, operand.value))
        else:
            result.append(InstructionTextToken(InstructionTextTokenType.TextToken, operand.text))
        return result


    def get_instruction_text(self, data, addr):
        opcode = data[0]
        inst_data = data
        if addr > 0:
            if addr not in self.opcode_xor_keys:
                raise Exception("no opcode xor key at 0x%x" % (addr))
            else:
                opcode ^= self.opcode_xor_keys[addr]
                opcode &= 0x7f
                inst_data = bytes([opcode]) + data[1:]

        inst = instructions[opcode](inst_data)
        inst.parse(inst_data)

        self.opcode_xor_keys[addr + inst.size] = inst.key

        result = []
        opcode_text = inst.text
        if (len(inst.operands)) > 0:
            operand = inst.operands[0]
            operand_size = 0
            if isinstance(operand, OperandPC) or isinstance(operand, OperandDP) or isinstance(operand, OperandData):
                operand_size = operand.data_size.value
            else:
                operand_size = operand.op_size

            if operand_size == 1:
                opcode_text += '.b'
            elif operand_size == 2:
                opcode_text += '.w'
            elif operand_size == 4:
                opcode_text += '.d'
        result.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, opcode_text))

        # process operands
        if len(inst.operands) > 0:
            result.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))

            for i in range(len(inst.operands)):
                operand = inst.operands[i]
                result.extend(self.get_operand_tokens(operand))
                if i != len(inst.operands) - 1:
                    result.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '))

        return result, inst.size


    def get_instruction_low_level_il(self, data, addr, il):
        return None