#include "gui.h"
#include "VMProtectSDK.h"
#include "memscan.h"
#include <Shlwapi.h>
static bool scan_finished = false;

#define R_PROTO_OBFUSCATE(p, v) *(int*)(int)(p) = (int)(v) - (int)(p)
#define RL_CLOSURE_OBFUSCATE(p, v) *(int*)(int)(p) = (int)(v) - (int)(p)

int __fastcall sub_6EC3D40(int a1, int a2)
{
	return a1 ^ 9837702 * a2 & 0x3FC01FF ^ _rotr(a1, 7) ^ _rotl(a1, 13);
}

int __fastcall sub_6EC3F10(unsigned int a1, int a2)
{
	unsigned int v2; // ebx
	int v3; // esi
	unsigned int v4; // eax
	int v6; // [esp+Ch] [ebp-8h]
	int v7; // [esp+10h] [ebp-4h]

	v6 = a2;
	v2 = a1 & 0x1FF;
	v3 = 0;
	v7 = (unsigned __int8)(a1 >> 18);
	while (1)
	{
		v4 = sub_6EC3D40(v3 & 0x3FFFFFF | 0x14000000, a2);
		if ((v4 & 0xFC000000) == 335544320 && (unsigned __int8)(v4 >> 18) == v7 && (v4 & 0x1FF) == v2)
			return v3 & 0x3FFFFFF | 0x14000000;
		if (++v3 >= 0x3FFFFFF)
			break;
		a2 = v6;
	}
	return 0;
}

int __fastcall sub_6EC3D20(int a1, int a2)
{
	return a1 ^ -10065 * a2 & 0x3FFFF ^ _rotr(a1, 6) ^ _rotl(a1, 9);
}

int __fastcall sub_6EC3EA0(int a1, int a2)
{
	int v2; // eax
	int v3; // ebx
	int v4; // esi
	int v5; // ecx
	int v7; // [esp+Ch] [ebp-4h]

	v2 = a2;
	v3 = a1 & 0x3FFFF;
	v7 = a2;
	v4 = 0;
	while (1)
	{
		v5 = sub_6EC3D20(v4 & 0x3FFFFFF | 0x50000000, v2);
		if ((v5 & 0xFC000000) == 1342177280 && v3 == (v5 & 0x3FFFF))
			return v4 & 0x3FFFFFF | 0x50000000;
		if (++v4 >= 0x3FFFFFF)
			break;
		v2 = v7;
	}
	return 0;
}


int sub_20CAB5D0(int a1, int a2, int a3, int a4, int a5)
{
	int v5; // edx@1
	int result; // eax@1
	signed int v7; // edi@1
	signed int v8; // ebx@1
	int v9; // esi@2
	int v10; // edx@2

	v5 = a2;
	result = 0;
	v7 = 1;
	v8 = 32;
	do
	{
		v9 = (v5 + a3 * result) ^ (a5 + v5 + a4 * result);
		v10 = result | v7;
		if ((v7 & v9) == (a1 & v7))
			v10 = result;
		v7 *= 2;
		result = v10;
		v5 = a2;
	} while (--v8);
	return result;
}

unsigned int __cdecl sub_20CAB900(int a1, int a2)
{
	unsigned int v2; // ebx@1
	int v3; // eax@1
	int v4; // edx@1
	int v5; // ebx@2
	unsigned int v6; // eax@2
	int v7; // eax@4
	int *v8; // ebx@4
	unsigned int v9; // ecx@4
	signed int v10; // edx@4
	unsigned int v11; // edi@6
	int v12; // esi@6
	int v13; // ebx@8
	unsigned int v14; // esi@11
	int v15; // edx@11
	int v16; // eax@11
	unsigned int v17; // edi@12
	int v18; // edx@12
	signed int v19; // ebx@12
	int v20; // esi@14
	bool v21; // zf@15
	unsigned int result; // eax@20
	int v23; // edx@20
	int v24[32]; // [sp+0h] [bp-A4h]@3
	unsigned int v25; // [sp+80h] [bp-24h]@2
	int v26; // [sp+84h] [bp-20h]@5
	int v27; // [sp+88h] [bp-1Ch]@7
	unsigned int v28; // [sp+8Ch] [bp-18h]@1
	int v29; // [sp+90h] [bp-14h]@1
	int v30; // [sp+94h] [bp-10h]@1
	int v31; // [sp+98h] [bp-Ch]@4
	int *v32; // [sp+9Ch] [bp-8h]@2
	unsigned int v33; // [sp+A0h] [bp-4h]@4
	unsigned int v34; // [sp+ACh] [bp+8h]@1

	v28 = 8388673;
	v2 = a1 & 0xFC03FFFF;
	v3 = 0;
	v34 = a1 & 0xFC03FFFF;
	v4 = -10065 * a2 & 0x3FFFF;
	v30 = 0;
	v29 = -10065 * a2 & 0x3FFFF;
	while (1)
	{
		v25 = v2 | (v3 << 18);
		v5 = 0;
		v32 = (int *)((v25 ^ v4) & 0x3FFFFFF | 0x50000000);
		v6 = v28;
		do
		{
			v24[v5] = (v6 << (v5 & 0x1F)) | (v6 >> (-(v5 & 0x1F) & 0x1F));
			++v5;
		} while (v5 < 0x20);
		v7 = (int)v32;
		v8 = v24;
		v9 = 0;
		v32 = v24;
		v10 = 1;
		v33 = 0;
		v31 = 1;
		do
		{
			v26 = *v8;
			if (!(v26 & v10))
			{
				v11 = v9 + 1;
				v12 = _rotl(v10, 1);
				if (v9 + 1 < 0x20)
				{
					v27 = 1 << v9;
					while (1)
					{
						v13 = v24[v11];
						v9 = v33;
						if (v13 & v27)
							break;
						++v11;
						v12 = _rotl(v12, 1);
						if (v11 >= 0x20)
							goto LABEL_12;
					}
					v14 = v7 & v12;
					v15 = v7 & ~(v10 | (1 << v11));
					v16 = v31 & v7;
					*v32 = v13;
					v24[v11] = v26;
					v9 = v33;
					v7 = (v14 >> (v11 - v33)) | v15 | (v16 << (v11 - v33));
				}
			}
		LABEL_12:
			v17 = 0;
			v18 = _rotl(1, v9);
			v31 = v18;
			v19 = 1;
			do
			{
				if (v17 != v9)
				{
					v20 = v24[v17];
					if (v20 & v18)
					{
						v24[v17] = v20 ^ *v32;
						v9 = v33;
						v21 = (v7 & (unsigned int)v19) >> v17 == (v7 & (unsigned int)v18) >> v33;
						v18 = v31;
						if (v21)
							v7 &= ~(1 << v17);
						else
							v7 |= 1 << v17;
					}
				}
				++v17;
				v19 = _rotl(v19, 1);
			} while (v17 < 0x20);
			++v9;
			v8 = v32 + 1;
			v10 = _rotl(v18, 1);
			v33 = v9;
			++v32;
			v31 = v10;
		} while (v9 < 0x20);
		result = v7 & 0x3FFFFFF | 0x50000000;
		v23 = (result ^ v29 ^ (result >> 6) ^ ((result << 9) | ((unsigned __int64)result >> 23))) & 0x3FFFFFF | 0x50000000;
		if (v25 == v23 && (v23 & 0xFC000000) == 1342177280)
			return result;
		v3 = v30 + 1;
		v30 = v3;
		if (v3 > 255)
			return 0;
		v4 = v29;
		v2 = v34;
	}
}

unsigned int jmp_enc2(unsigned int a1, int a2)
{
	unsigned int A = a1 & 0xFC000000;
	unsigned int result = sub_20CAB900(a1, a2);
	unsigned int v14 = result & 0x3FFFFFF | 1342177280;
	goto LABEL_16;
	if (A != 1811939328)
	{
	LABEL_16:
		if (A != -2013265920)
			goto LABEL_20;
	}
LABEL_20:
	if (A == 2080374784)
	{
		result = sub_20CAB5D0(
			v14,
			a2,
			(1488630376 ^ 1788176131) ^ 0xB4B ^ 2891 ^ 0x33DC0DC4,
			(1488630376 ^ 1788176131) ^ 0xB4B ^ 2891 ^ 0xCC169EA3,
			(1488630376 ^ 1788176131) ^ 0xB4B ^ 2891 ^ 0xCD84310A);
		v14 = result & 0x3FFFFFF | 0x7C000000;
	}
	if (A == -1811939328)
	{
		result = sub_20CAB5D0(
			v14,
			a2,
			(1488630376 ^ 1788176131) ^ 0xB4B ^ 2891 ^ 0x32B9C9ED,
			(1488630376 ^ 1788176131) ^ 0xB4B ^ 2891 ^ 0x33DC0DC4,
			(1488630376 ^ 1788176131) ^ 0xB4B ^ 2891 ^ 0xCC109656);
		v14 = result & 0x3FFFFFF | 0x94000000;
	}

	return v14;
}

int return_enc(int a1, int a2)
{
	int v11;
	int v12;
	int v23;
	int v13;
	int v14;
	int v4 = a1;
	int v15;
	int v16;
	int v17;
	v11 = a2;
	v12 = 0;
	v23 = 32;
	v13 = 1;
	v14 = a2 - 1577854801;
	do
	{
		v15 = (v12 * v14 + 641680189) ^ (v11 * v12 + 1470882913);
		v16 = v12 | v13;
		v11 = a2;
		if ((v13 & v15) == (v4 & v13))
			v16 = v12;
		v13 *= 2;
		v17 = v23-- == 1;
		v12 = v16;
		v14 = a2 - 1577854801;
	} while (!v17);
	return ((v4 ^ v12) & 0x3FFFFFF ^ v4);
}

unsigned int  sub_6EC4400(int a1, int a2 , int a3)
{
	int v3; // edi
	unsigned int v4; // edx

	v3 = a1;
	v4 = *(DWORD *)(a2 + 24) + 4 * ((a3 + 4) % (unsigned int)(*(DWORD *)(a2 + 44) - 4));
	return ((unsigned int)(v3 * *(DWORD *)(a2 + 24 + v4)) >> 26)
		+ ((unsigned int)(v3 * *(DWORD *)(a2 + 24 + v4 + 4)) >> 26)
		+ ((unsigned int)(v3 * *(DWORD *)(a2 + 24 + v4 + 8)) >> 26)
		+ ((unsigned int)(v3 * *(DWORD *)(v4 + a2 + 24 + 12)) >> 26);
}

int __fastcall sub_6EC4450(int a1, int a2)
{
	int v2; // edi
	int v3; // ecx
	signed int v4; // edx
	int v5; // esi
	int v6; // ebx
	int v7; // edi
	int v8; // ebx
	signed int v9; // esi
	int v11; // [esp+1Ch] [ebp-24h]
	int v12; // [esp+20h] [ebp-20h]
	int v13; // [esp+24h] [ebp-1Ch]

	v12 = a2;
	v11 = a1;
	v2 = *(DWORD *)(a1 + 56);
	v3 = *(DWORD *)(a1 + 36);
	v4 = *(DWORD *)(v11 + 44);
	v5 = *(unsigned __int8 *)(v11 + 78)
		+ ((*(unsigned __int8 *)(v11 + 76) + ((*(unsigned __int8 *)(v11 + 79) + (*(unsigned __int8 *)(v11 + 77) << 8)) << 8)) << 8);
	v6 = -1395309893 * v3 - 1838748549 * v5 - 1993746777 * v2 - 1125194579 * v4;
	v13 = -1395309893 * v3 - 1838748549 * v5 - 1993746777 * v2 - 1125194579 * v4;
	v7 = 476035360 * v3 + 1546808719 * v2 - 2088292391 * v5 - 706264423 * v4;
	if (v4 < 8)
	{
		printf("v4 <= 8\n");
		v8 = v13 ^ v7;
	}
	else
	{
		v8 = v13 + sub_6EC4400(v12, v11, v6);
		v7 += sub_6EC4400(v12, v11, v7);
		
	}

	return v8;
	
}

namespace lua_to_roblox
{
	VOID convert_proto(int rl, Proto* p, DWORD rp, int* rpnups) { // same order as readProto
																	 /* main conversion of vanilla proto to roblox proto */

		R_PROTO_OBFUSCATE(rp + 16, RLUAS_NEW(rl, getstr(p->source)));

		*(unsigned int*)(rp + 48) = p->sizep;
		auto* rpp_mem = (int*)RLUAM_MALLOC(rl, sizeof(int*) * p->sizep);
		R_PROTO_OBFUSCATE(rp + 20, rpp_mem);

		for (int k = 0; k < p->sizep; k++) {
			rpp_mem[k] = rluaF_newproto(rl);
			convert_proto(rl, p->p[k], rpp_mem[k], rpnups);
		}




		*(unsigned int*)(rp + 28) = p->sizek;
		auto* rp_k_mem = (r_tvalue*)RLUAM_MALLOC(rl, sizeof(r_tvalue) * p->sizek);
		R_PROTO_OBFUSCATE(rp + 12, rp_k_mem);

		for (int k = 0; k < p->sizek; k++) {
			TValue* o = &p->k[k];
			r_tvalue* ro = &rp_k_mem[k];
			switch (o->tt) {
			case LUA_TNIL:
				ro->tt = RLUA_TNIL;
				ro->value.n = 0;
				break;
			case LUA_TBOOLEAN:
				ro->tt = RLUA_TBOOLEAN;
				ro->value.b = o->value.b;
				break;
			case LUA_TNUMBER:
				ro->tt = RLUA_TNUMBER;
				ro->value.n = r_xor_number(&o->value.n);
				break;
			case LUA_TSTRING:
				ro->tt = RLUA_TSTRING;
				ro->value.gc = RLUAS_NEW(rl, getstr((TString*)o->value.gc));
				break;
			default:
				break;
			}
		}

		*(unsigned int*)(rp + 72) = p->sizecode;
		auto* rp_code_mem = (int*)RLUAM_MALLOC(rl, sizeof(int*) * p->sizecode);
		int a3 = rp;
		int v5 = rl;
		DWORD dwOld;
		VirtualProtect((LPVOID)(VMCheckAddy - 3), 2, PAGE_READONLY, &dwOld);
		R_PROTO_OBFUSCATE(rp + 32, rp_code_mem);

		for (int k = 0; k < p->sizecode; k++) {
			/* instruction conversion */

			Instruction inst = p->code[k]; //vanilla instruction
			int r_inst = 0;
			OpCode op = GET_OPCODE(inst);

			RSET_OPCODE(r_inst, get_roblox_opcode[op]);

			switch (getOpMode(op)) {
			case iABC:
				RSETARG_A(r_inst, GETARG_A(inst));
				RSETARG_B(r_inst, GETARG_B(inst));
				RSETARG_C(r_inst, GETARG_C(inst));
				break;
			case iABx:
				RSETARG_A(r_inst, GETARG_A(inst));
				RSETARG_Bx(r_inst, GETARG_Bx(inst));
				break;
			case iAsBx:
				RSETARG_A(r_inst, GETARG_A(inst));
				RSETARG_sBx(r_inst, GETARG_sBx(inst));
				break;
			
			}

			/* enc has been added this time! includes eternals really shit wrong encryption he gave everyone as an attempt to seem smarter in the eyes of others */
			switch (op) {
			case OP_JMP:
				r_inst = r_inst >> 26 << 26 | sub_6EC3EA0(r_inst, k);
				break;
			case OP_CALL:
				r_inst = r_inst >> 26 << 26 | call_enc(r_inst, k);
				break;
			case OP_TAILCALL:
			case OP_RETURN:
				r_inst = r_inst >> 26 << 26 | return_enc(r_inst, k);//dax_encode_op(r_inst, k, 1470882913, k - 1577854801, 641680189) & 0x3FFFFFF;
				break;
			case OP_CLOSURE:
				r_inst = r_inst >> 26 << 26 | closure_enc(r_inst, k);
				break;
			case OP_SETUPVAL:
				r_inst = r_inst >> 26 << 26 | sub_6EC3F10(r_inst, k);
			case OP_MOVE:
				r_inst = r_inst & 0xFFFC21FF | 0x2000;
				break;
			
			}

			rp_code_mem[k] = r_inst * encode_key;
		}
		// sizelocvars set
		*(unsigned int*)(rp + 64) = p->sizelineinfo;
		auto* rp_lineinfo_mem = (int*)RLUAM_MALLOC(rl, sizeof(int*) * p->sizelineinfo);
		R_PROTO_OBFUSCATE(rp + 8, rp_lineinfo_mem);

		for (int k = 0; k < p->sizelineinfo; k++) {
			rp_lineinfo_mem[k] = p->lineinfo[k] ^ (k << 8);
		}

		// sizeupvalues set
		*(BYTE *)(rp + 79) = p->maxstacksize;
		*(BYTE *)(rp + 78) = p->is_vararg;
		*rpnups += p->nups;  *(BYTE *)(rp + 76) = p->nups;
		*(BYTE *)(rp + 77) = p->numparams;
	}

	VOID set_l_closure(int rl, LClosure* lcl) {
		Proto* p = lcl->p;
		DWORD rp = rluaF_newproto(rl);
		int rpnups = 0;

		convert_proto(rl, p, rp, &rpnups);
		DWORD rlcl = rluaF_newLclosure(rl, rpnups, *(int*)(rl + RL_L_GT));
		*(DWORD*)(rlcl + 16) = rlcl + rp + 16;

		if (rpnups)
		{
			int v304 = rlcl + 4 * rpnups + 20;
			do
			{
				*(int*)(v304 - 4) = 0;
				v304 -= 4;
				--rpnups;
			} while (rpnups);
		}

		rlua_pushlclosure(rl, rlcl);
	}

	VOID call_l_closure(int rl, LClosure* lcl) {
		set_l_closure(rl, lcl);
		r_spawn(rl);
	}

	VOID execute_script(int rl, lua_State* l, std::string source) {
		int r_thread = r_lua_newthread(rl);
		set_encode_key(r_thread, &encode_key);
		

		int unk[] = { NULL, NULL };

		
	
		
		r_sandbox_thread(r_thread, 6, (int)unk);

		//r_init_thread(r_thread);

		if (luaL_loadstring(l, source.c_str())) {
			printf("Error: %s\n", lua_tostring(l, -1));
			lua_pop(l, 1);
		}

		else {
			util::pause();
			TValue* o = (l->top) - 1;
			LClosure* lcl = &clvalue(o)->l;
			call_l_closure(r_thread, lcl);
			lua_pop(l, 1);
			util::resume();
		}

		printf("\nlstack: %d\n", lua_gettop(l));
		printf("rstack: %d\n", RLUA_GETTOP(rl));
	}
}

void execute_script(int rL, lua_State* L, const std::string &source) {
	lua_to_roblox::execute_script(rL, L, source);
}