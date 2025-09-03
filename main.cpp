//
// 1.���������DLL·�� %appdata%/Binary Ninja/plugins/
// 2.�õ���ʲô�汾��BinaryNinja��Ҫ�л���SDK��Ӧ�İ汾,��Ȼ���е�ʱ��ᱨ�汾��ƥ��
//

#include "examples/example1.h"
#include "Internal.h"

using namespace BinaryNinja;

extern "C"
{
	extern "C" 
	{ 
		// [Default] This plugin was built for a newer version of Binary Ninja (XX). 
		// Please update Binary Ninja or rebuild the plugin with the matching API version (XX).
		BINARYNINJAPLUGIN uint32_t CorePluginABIVersion() {  
			// git pull origin dev
			return BN_CURRENT_CORE_ABI_VERSION;
		} 
	}

	BINARYNINJAPLUGIN bool CorePluginInit() 
	{
		internal::Init();

		return true;
	}

	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
	}
}
