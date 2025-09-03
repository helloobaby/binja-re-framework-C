//
// 1.编译出来的DLL路径 %appdata%/Binary Ninja/plugins/
// 2.用的是什么版本的BinaryNinja就要切换到SDK对应的版本,不然运行的时候会报版本不匹配
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
