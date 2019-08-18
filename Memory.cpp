//Memory.cpp
#include "stdafx.h"

bool isHex(char c)
{
	return (c > 47 && c < 58) || (c > 64 && c < 91) || (c > 96 && c < 123);
}

bool createPattern(const std::string& pattern, std::string& pattern_result, std::string& mask_result)
{
	size_t l = pattern.size();
	if (l-- <= 0)
		return false;
	std::stringstream pattern_s;
	std::stringstream mask_s;
	for (size_t i = 0; i < l; i++)
	{
		if (!isHex(pattern[i]))
		{
			if (pattern[i] == 63)
			{
				pattern_s << "\x90";
				mask_s << '?';
			}
		}
		else
		{
			char buffer[2];
			buffer[0] = pattern[i];
			buffer[1] = (l >= i + 1 && isHex(pattern[i + 1])) ? pattern[++i] : 0;
			pattern_s << static_cast<char>(strtol(buffer, nullptr, 16));
			mask_s << 'x';
		}
	}
	pattern_result = pattern_s.str();
	mask_result = mask_s.str();
	return true;
}

DWORD getImageSize(uint64_t moduleBase)
{
	const IMAGE_NT_HEADERS*	header = reinterpret_cast<const IMAGE_NT_HEADERS*>(moduleBase + (reinterpret_cast<const IMAGE_DOS_HEADER*>(moduleBase))->e_lfanew);
	return header->OptionalHeader.SizeOfCode;
}

char* byteCompare(char* ptr, size_t size, const std::string& pattern, const std::string& mask, int find)
{
	char* end = ptr + size;
	size_t matchlen = mask.size();
	for (int i = 0, found = 0; ptr != end; ptr++)
	{
		if (*ptr == pattern[i] || mask[i] == 63)
		{
			if (++i == matchlen)
			{
				if (find != found)
				{
					i = 0;
					found++;
				}
				else
				{
					ptr -= matchlen - 1;
					return ptr;
				}
			}
		}
		else if (*ptr == pattern[0] || mask[0] == 63)
		{
			ptr--;
			i = 0;
		}
		else
		{
			i = 0;
		}
	}
	return nullptr;
}

char* virtualPtrScan(const std::string& pattern, const std::string& mask, uintptr_t startAddress, int find)
{
	MEMORY_BASIC_INFORMATION mbi;
	char* ptr = reinterpret_cast<char*>(startAddress);
	char* end = nullptr;
	char* res = nullptr;
	size_t maskLen = mask.size();
	int found = 0;
	while (sizeof(mbi) == VirtualQuery(end, &mbi, sizeof(mbi)))
	{
		ptr = end;
		end += mbi.RegionSize;
		if (mbi.Protect != PAGE_READWRITE || mbi.State != MEM_COMMIT)
			continue;
		res = byteCompare(ptr, mbi.RegionSize, pattern, mask, find);
		if (found != find && res != nullptr)
		{
			res = nullptr;
			found++;
		}
		mbi = {};
		if (res != nullptr)
			break;
	}
	return res;
}

char* ptrScan(const std::string& pattern, const std::string& mask, uintptr_t startAddress, int find)
{
	uintptr_t base = (uintptr_t)GetModuleHandleA(nullptr);
	if (startAddress < base)
		startAddress = base;
	size_t matchlen = mask.size();
	return byteCompare(reinterpret_cast<char*>(startAddress), getImageSize(base), pattern, mask, find);
}

char* ptrScan(const std::string& pattern, uintptr_t startAddress, int find)
{
	std::string sub_ptr;
	std::string sub_mask;
	createPattern(pattern, sub_ptr, sub_mask);
	return ptrScan(sub_ptr, sub_mask, startAddress, find);
}

char* virtualPtrScan(const std::string& pattern, uintptr_t startAddress, int find)
{
	std::string sub_ptr;
	std::string sub_mask;
	createPattern(pattern, sub_ptr, sub_mask);
	return virtualPtrScan(sub_ptr, sub_mask, startAddress, find);
}

char* rel(char* ptr, int offset)
{
	const int JUMP_SIZE = 4;
	return reinterpret_cast<char*>(ptr) + *reinterpret_cast<int*>(ptr + offset) + (offset + JUMP_SIZE);
}