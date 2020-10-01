#include <Windows.h>
#include <MinHook.h>
#include <string>
#include <sstream>
#include <fstream>
#include <vector>
#include <locale>
#include <codecvt>
#include <filesystem>
#include <regex>
#include <intrin.h>
namespace fs = std::filesystem;

#include <shlobj.h>

#include "patterns.hpp"
#include "dfm.hpp"
#include "json.hpp"
#include "flt80.h"

std::string module_name = "FLEngine_x64.dll";

// winapi hooks

using fn_LoadResource_t = HGLOBAL( __stdcall* )( HMODULE, HRSRC );
fn_LoadResource_t orig_LoadResource;

using fn_LockResource_t = LPVOID( __stdcall* )( HGLOBAL );
fn_LockResource_t orig_LockResource;

using fn_SizeofResource_t = DWORD( __stdcall* )( HMODULE, HRSRC );
fn_SizeofResource_t orig_SizeofResource;

// FL hooks

using fn_get_color_t = uint64_t( * )( uint32_t );
fn_get_color_t orig_get_mixer_color;

using fn_unk_set_color_t = uint64_t( * )( uint64_t, uint64_t, uint64_t, uint64_t );
fn_unk_set_color_t orig_unk_set_color;

using fn_get_registry_value_t = uint64_t( * )( uint64_t, uint64_t, const wchar_t*, uint32_t );
fn_get_registry_value_t orig_get_registry_value;

using fn_get_pl_track_color_t = uint64_t( * )( uint64_t );
fn_get_pl_track_color_t orig_get_pl_track_color;

std::wstring skin_path;

struct resource_t {
	std::string name;
	size_t new_size;

	HRSRC _rsrc;
	HGLOBAL _mem;
	HMODULE _module;
	SIZE_T _size;
};

std::vector<resource_t> resources;

bool resources_loaded = false;

BOOL CALLBACK EnumResNameProc(
  _In_opt_ HMODULE  hModule,
  _In_     LPCTSTR  lpszType,
  _In_     LPTSTR   lpszName,
  _In_     LONG_PTR lParam
) {
	const auto hrsrc = FindResourceA( hModule, lpszName, lpszType );

	resource_t resource;
	resource._rsrc = hrsrc;

	const auto _mem = orig_LoadResource( hModule, hrsrc );
	const auto data = orig_LockResource( _mem );

	// TPF0 header
	if ( *reinterpret_cast< uint32_t* >( data ) == 0x30465054 ) {
		// only add DFM files
		resources.push_back( resource );
	}

	return true;
}

void load_resources() {
	const auto mod = GetModuleHandleA( module_name.c_str() );

	EnumResourceNamesA( mod, RT_RCDATA, EnumResNameProc, NULL );
}

struct col_replacement_t {
	uint32_t a, b;
};
std::vector<col_replacement_t> dfm_replacements = {
	//{ 0x676259, 0x272727 },
	//{ 0x6d685f, 0x272727 },
	//{ 0x4d483f, 0x1f1f1f },
	//{ 0x74735f, 0x1b1b1b },
	//{ 0x666553, 0x1f1f1f },
	//{ 0x6d685f, 0x1f1f1f },
	//{ 0x4b463e, 0x1f1f1f },
	//{ 0x3d3830, 0x1f1f1f },
	//{ 0x453c31, 0x272727 },
	//{ 0x5e5950, 0x292929 }
};

std::vector<col_replacement_t> hook_replacements = {
	//{ 0x313C45, 0x232323 }, // pattern picker background
	//{ 0x34444e, 0x1F1F1F }, // playlist background
	//{ 0x5F686D, 0x29363E }, // mixer eq background
	//{ 0x182832, 0x33343C }, // playlist grid lines
	//{ 0x2a3a44, 0x2C353A }, // playlist grid lines
	//{ 0x22323c, 0x3C3D45 }, // playlist grid lines
	//{ 0x10202a, 0x2C353A }, // playlist grid lines
	//{ 0x1e2b31, 0x171F22 },
	//{ 0x716C63, 0x292929 }
};

struct dfm_t {
	std::string obj_name;
	std::string val_name;
	dfm::val v;
	bool check_parent = false;
	bool no_create;
	std::string parent_name;
};

std::vector<dfm_t> dfms = {};

bool
replace_mixer_tracks = false,
replace_grid_color = false,
replace_buttons = false,
replace_browser_color = false,
replace_browser_files_color = false,
replace_sequencer_blocks = false,
replace_sequencer_blocks_highlight = false,
replace_sequencer_blocks_alt = false,
replace_sequencer_blocks_alt_highlight = false,
replace_default_pattern_color = false,
replace_default_playlist_track_color = false,
replace_mixer_level_gradient = false,
replace_mixer_level_background_gradient = false,
replace_peak_meter = false;

bool hide_name = false;

uint32_t
mixer_color = 0,
grid_color = 0,
button_colors = 0,
browser_color = 0,
browser_files_color = 0,
sequencer_blocks = 0,
sequencer_blocks_highlight = 0,
sequencer_blocks_alt = 0,
sequencer_blocks_alt_highlight = 0,
default_pattern_color = 0,
default_playlist_track_color = 0,
mixer_level_gradient1_a,
mixer_level_gradient1_b,
mixer_level_gradient2_a,
mixer_level_gradient2_b,
mixer_level_gradient3_a,
mixer_level_gradient3_b,
mixer_level_clipping,
mixer_level_background_gradient_a,
mixer_level_background_gradient_b,
peak_meter_a,
peak_meter_b,
peak_meter_c;

void do_button_color_replacements( dfm::object& obj ) {
	for ( auto& c : obj.get_children() ) {
		if ( c.get_children().size() > 0 ) {
			do_button_color_replacements( c );
		}

		if ( !c.is_object() ) continue;

		if ( c.get_name_parent() == "TQuickBtn" ) {
			if ( c.get_name() == "StartBtn"
				 || c.get_name() == "StopBtn" 
				 || c.get_name() == "RecBtn" ) {
				for ( auto& c2 : c.get_children() ) {
					if ( c2.get_name() == "Color" ) {
						c2.get_val().m_num_val = button_colors;
					}
				}
			} else if ( c.get_name() != "PatBtn"){
				dfm::val v;
				v.m_type = dfm::type_t::int32;
				v.m_num_val = button_colors;

				dfm::object o;
				o.setup( "ExtraColor", v );

				c.add_child( o );
			}

			//printf( "%s => (%s: %s)\n", obj.get_name().c_str(), c.get_name().c_str(), c.get_name_parent().c_str() );
		}
	}
}

void do_color_replacements( dfm::object& obj ) {
	for ( auto& c : obj.get_children() ) {
		if ( c.get_children().size() > 0 ) {
			do_color_replacements( c );
		}

		if ( c.get_val().m_type != dfm::type_t::int32 ) continue;
		if ( c.get_name().find( "Color" ) == std::string::npos ) continue;

		for ( auto& replacement : dfm_replacements ) {
			if ( ( c.get_val().m_num_val & 0xFFFFFF ) == ( replacement.a & 0xFFFFFF ) ) {
				c.get_val().m_num_val = replacement.b | ( replacement.a & 0xFF000000 );

				break;
			}
		}
	}
}

void do_dfm_replacements( dfm::object& obj ) {
	for ( auto& c : obj.get_children() ) {
		if ( c.get_children().size() > 0 ) {
			do_dfm_replacements( c );
		}

		for ( auto& dfm : dfms ) {
			if ( dfm.obj_name == "*" || c.get_name() == dfm.obj_name ) {
				if ( dfm.check_parent && obj.get_name() != dfm.parent_name ) continue;

				bool exists = false;
				
				for ( auto& c2 : c.get_children() ) {
					if ( c2.get_name() == dfm.val_name ) {
						exists = true;

						c2.set_val( dfm.v );

						break;
					}
				}

				if ( !exists && !dfm.no_create ) {
					dfm::object o;
					o.setup( dfm.val_name, dfm.v );

					c.add_child_before( o );
				}
			}
		}
	}
}

vec_byte_t process_resource( void* memory, size_t size ) {
	vec_byte_t raw_buffer;
	raw_buffer.assign(
		reinterpret_cast< char* >( memory ),
		reinterpret_cast< char* >( memory ) + size
	);

	auto obj = dfm::parse( raw_buffer );

	do_color_replacements( obj );
	if ( replace_buttons ) do_button_color_replacements( obj );
	do_dfm_replacements( obj );

	return obj.get_full_binary().raw();
}

uint64_t hk_get_mixer_color( uint32_t a1 ) {
	auto res = orig_get_mixer_color( a1 );

	if ( replace_mixer_tracks && mixer_color ) {
		res = mixer_color;
	}

	return res;
}

// i put this hook here so that skins alone can override the grid color without a reg file
uint64_t hk_get_registry_value( uint64_t a1, uint64_t a2, const wchar_t* name, uint32_t default_value ) {
	// grid color
	if ( replace_grid_color && wcscmp( name, L"Grid color" ) == 0 ) {
		return grid_color;
	}

	return orig_get_registry_value( a1, a2, name, default_value );
}

void* get_pl_track_color_ret_address = 0;
uint64_t hk_get_pl_track_color( uint64_t a1 ) {
	const auto ret_addr = _ReturnAddress();
	if ( replace_default_playlist_track_color
		 && ret_addr == get_pl_track_color_ret_address
		 && ( a1 & 0xFFFFFF ) == 0x565148 ) {
		return ( a1 & 0xFF000000 ) | ( default_playlist_track_color & 0xFFFFFF );
	}

	return orig_get_pl_track_color( a1 );
}

#include <random>

// i think this is used for when different panels' colors are set in FL
// it also might have more args :shrug:
uint64_t hk_unk_set_color( uint64_t a, uint64_t b, uint64_t col, uint64_t d ) {
	for ( auto& replacement : hook_replacements ) {
		if ( ( col & 0xFFFFFF ) == ( replacement.a & 0xFFFFFF ) ) {
			col = replacement.b | ( replacement.a & 0xFF000000 );

			break;
		}
	}

	return orig_unk_set_color( a, b, col, d );
}

template <typename T>
void force_write( uintptr_t address, T data ) {
	DWORD old_protect;
	VirtualProtect( reinterpret_cast< void* >( address ), sizeof( T ), PAGE_READWRITE, &old_protect );
	*reinterpret_cast< T* >( address ) = data;
	VirtualProtect( reinterpret_cast< void* >( address ), sizeof( T ), old_protect, &old_protect );
}

// LoadResource hook
HGLOBAL __stdcall hk_LoadResource(
  HMODULE hModule,
  HRSRC   hResInfo
) {
	if ( !resources_loaded ) {
		load_resources();

		const auto get_mixer_color_addy =
			reinterpret_cast< void* >( pattern::find( module_name.c_str(), "55 48 83 EC 30 48 8B EC 89 C8" ) );

		MH_CreateHook( get_mixer_color_addy, hk_get_mixer_color, reinterpret_cast< void** >( &orig_get_mixer_color ) );
		MH_EnableHook( get_mixer_color_addy );

		const auto unk_set_color_addy =
			reinterpret_cast< void* >( pattern::find_rel( module_name.c_str(), "E8 ? ? ? ? 48 8B 45 48 F2 0F 2A 80 ? ? ? ?", 0, 1, 5 ) );

		MH_CreateHook( unk_set_color_addy, hk_unk_set_color, reinterpret_cast< void** >( &orig_unk_set_color ) );
		MH_EnableHook( unk_set_color_addy );




		const auto get_registry_value_addy = 
			reinterpret_cast< void* >( pattern::find_rel( module_name.c_str(), "E8 ? ? ? ? 81 F8 ? ? ? ? 74 0C", 0, 1, 5 ) );

		MH_CreateHook( get_registry_value_addy, hk_get_registry_value, reinterpret_cast< void** >( &orig_get_registry_value ) );
		MH_EnableHook( get_registry_value_addy );

		const auto get_pl_track_color_addy =
			reinterpret_cast< void* >( pattern::find_rel( module_name.c_str(), "C7 C1 ? ? ? ? E8 ? ? ? ? 48 63 CE 48 8B D1", 6, 1, 5 ) );
		get_pl_track_color_ret_address = 
			reinterpret_cast< void* >( pattern::find_rel( module_name.c_str(), "E8 ? ? ? ? 40 B6 01 EB 0F", 0, 1, 5 ) + 0x50 );

		MH_CreateHook( get_pl_track_color_addy, hk_get_pl_track_color, reinterpret_cast< void** >( &orig_get_pl_track_color ) );
		MH_EnableHook( get_pl_track_color_addy );

		if ( replace_browser_color ) {
			// .text:0000000001EC9131 4C 8B 6F 58         mov     r13, [rdi+58h]
			// .text:0000000001EC9135 8B 05 F9 83 3D 00   mov     eax, cs : dword_22A1534 // <-- the browser color
			auto browser_color_addy = pattern::find( module_name.c_str(), "4C 8B 6F 58" );
			browser_color_addy += 4;

			auto browser_color_rel = *reinterpret_cast< uint32_t* >( browser_color_addy + 2 );
			auto browser_color_ptr = reinterpret_cast< uint32_t* >( browser_color_addy + browser_color_rel + 6 );

			*browser_color_ptr = ( browser_color | 0xFF000000 );
		}



		if ( replace_browser_files_color ) {
			auto browser_color_addy = pattern::find( module_name.c_str(), "44 8B 2D ? ? ? ? 41 81 E5 ? ? ? ?" );

			auto browser_color_rel = *reinterpret_cast< uint32_t* >( browser_color_addy + 3 );
			auto browser_color_ptr = reinterpret_cast< uint32_t* >( browser_color_addy + browser_color_rel + 7 );

			*browser_color_ptr = ( browser_files_color | 0xFF000000 );
		}

		auto sequencer_colors = pattern::find_rel( module_name.c_str(), "48 8D 05 ? ? ? ? 8B 4C 24 40" );

		if ( replace_sequencer_blocks )
			*reinterpret_cast< uint32_t* >( sequencer_colors + 0x0 ) = ( sequencer_blocks | 0xFF000000 );

		if ( replace_sequencer_blocks_highlight )
			*reinterpret_cast< uint32_t* >( sequencer_colors + 0x8 ) = ( sequencer_blocks_highlight | 0xFF000000 );

		if ( replace_sequencer_blocks_alt )
			*reinterpret_cast< uint32_t* >( sequencer_colors + 0x4 ) = ( sequencer_blocks_alt | 0xFF000000 );

		if ( replace_sequencer_blocks_alt_highlight )
			*reinterpret_cast< uint32_t* >( sequencer_colors + 0xC ) = ( sequencer_blocks_alt_highlight | 0xFF000000 );

		if ( replace_default_pattern_color ) {
			auto replacement1_addy = pattern::find( module_name.c_str(), "74 1E C7 C1 ? ? ? ?" );
			if ( replacement1_addy ) replacement1_addy += 36;

			auto replacement2_addy = pattern::find( module_name.c_str(), "74 09 81 78 ? ? ? ? ?" );
			if ( replacement2_addy ) replacement2_addy += 5;

			const auto replacement3_addy = pattern::find_rel( module_name.c_str(), "48 8D 0D ? ? ? ? 48 63 DB" );

			if ( replacement1_addy ) force_write( replacement1_addy, default_pattern_color );
			if ( replacement2_addy ) force_write( replacement2_addy, default_pattern_color );
			if ( replacement3_addy ) force_write( replacement3_addy, default_pattern_color );

			// (these replacements are for FL 20.5 and below)
			{
				auto replacement4_addy = pattern::find_rel( module_name.c_str(), "E8 ? ? ? ? C7 C6 ? ? ? ? 8B 5C 24 28", 0, 1, 5 );
				if ( replacement4_addy ) replacement4_addy += 58;

				auto replacement5_addy = pattern::find_rel( module_name.c_str(), "48 8D 05 ? ? ? ? 8B 55 24 " );
				if ( replacement5_addy ) replacement5_addy += 8;

				if ( replacement4_addy ) force_write( replacement4_addy, default_pattern_color );
				if ( replacement5_addy ) force_write( replacement5_addy, default_pattern_color );
			}

			for ( auto occurence : pattern::find_all( module_name.c_str(), "81 78 08 48 51 56 00" ) ) {
				force_write( occurence + 3, default_pattern_color );
			}
		}

		// 48 8B 4D 60 C7 C2 ? ? ? ? 41 C7 C0 ? ? ? ? F3 0F 10 1D ? ? ? ? 48 0F B6 05 ? ? ? ? 88 44 24 20 C7 44 24 ? ? ? ? ? E8 ? ? ? ? 48 8B 4D 78 48 33 D2 48 8B 45 78 48 8B 30 FF 96 ? ? ? ? 48 8B 4D 60 48 8D 95 ? ? ? ? 41 C7 C0 ? ? ? ? E8 ? ? ? ? E9 ? ? ? ?

		if ( replace_mixer_level_gradient ) {
			auto replacement_addy1 = pattern::find( module_name.c_str(), "48 8B 4D 60 C7 C2 ? ? ? ? 41 C7 C0 ? ? ? ? F3 0F 10 1D ? ? ? ? 48 0F B6 05 ? ? ? ? 88 44 24 20 C7 44 24 ? ? ? ? ? E8 ? ? ? ? 48 8B 4D 78 48 33 D2 48 8B 45 78 48 8B 30 FF 96 ? ? ? ? 48 8B 4D 60 48 8D 95 ? ? ? ? 41 C7 C0 ? ? ? ? E8 ? ? ? ? 48 8D BD ? ? ? ?" );

			if ( replacement_addy1 ) {
				replacement_addy1 += 6;

				force_write( replacement_addy1, mixer_level_gradient1_a | 0xFF000000 );

				replacement_addy1 += 7;

				force_write( replacement_addy1, mixer_level_gradient1_b | 0xFF000000 );
			}

			auto replacement_addy2 = pattern::find( module_name.c_str(), "48 8B 4D 60 C7 C2 ? ? ? ? 41 C7 C0 ? ? ? ? F3 0F 10 1D ? ? ? ? 48 0F B6 05 ? ? ? ? 88 44 24 20 C7 44 24 ? ? ? ? ? E8 ? ? ? ? 48 8B 4D 78 48 33 D2 48 8B 45 78 48 8B 30 FF 96 ? ? ? ? 48 8B 4D 60 48 8D 95 ? ? ? ? 41 C7 C0 ? ? ? ? E8 ? ? ? ? E9 ? ? ? ?" );
			
			if ( replacement_addy2 ) {
				replacement_addy2 += 6;

				force_write( replacement_addy2, mixer_level_gradient2_a | 0xFF000000 );

				replacement_addy2 += 7;
			
				force_write( replacement_addy2, mixer_level_gradient2_b | 0xFF000000 );
			}

			auto replacement_addy3 = pattern::find( module_name.c_str(), "48 8B 4D 60 C7 C2 ? ? ? ? 41 C7 C0 ? ? ? ? F3 0F 10 1D ? ? ? ? 48 0F B6 05 ? ? ? ? 88 44 24 20 C7 44 24 ? ? ? ? ? E8 ? ? ? ? 48 8B 4D 78 48 33 D2 48 8B 45 78 48 8B 30 FF 96 ? ? ? ? 48 8B 4D 60 48 8D 95 ? ? ? ? 41 C7 C0 ? ? ? ? E8 ? ? ? ? 48 8B 4D 78");

			if ( replacement_addy3 ) {
				replacement_addy3 += 6;

				force_write( replacement_addy3, mixer_level_gradient3_a | 0xFF000000 );
				replacement_addy3 += 7;
				force_write( replacement_addy3, mixer_level_gradient3_b | 0xFF000000 );

			}

			auto clipping_addy = pattern::find( module_name.c_str(), "48 8B 4D 78 C7 C2 ? ? ? ? 48 8B 45 78 48 8B 30 FF 96 ? ? ? ? 48 8B 4D 78" );

			if ( clipping_addy ) {
				clipping_addy += 6;

				force_write( clipping_addy, mixer_level_clipping | 0xFF000000 );
			}
		}

		if (replace_mixer_level_background_gradient) {
			auto replacement_addy = pattern::find(module_name.c_str(), "48 8B 4D 60 C7 C2 ? ? ? ? 41 C7 C0 ? ? ? ? F3 0F 10 1D ? ? ? ?");

			if (replacement_addy) {
				replacement_addy += 6;
				force_write(replacement_addy, mixer_level_background_gradient_b | 0xFF000000);
				replacement_addy += 7;
				force_write(replacement_addy, mixer_level_background_gradient_a | 0xFF000000);
			}
		}

		if ( replace_peak_meter ) {
			auto replacement_addy = pattern::find( module_name.c_str(), "41 C7 C1 E0 E8 EC 00" );

			if ( replacement_addy ) {
				replacement_addy += 3;
				force_write( replacement_addy, peak_meter_a & ~0xFF000000 );
				replacement_addy += 8;
				force_write( replacement_addy, peak_meter_b & ~0xFF000000 );
				replacement_addy += 8;
				force_write( replacement_addy, peak_meter_c & ~0xFF000000 );
			}
		}

		if ( hide_name ) {
			const auto name_str_addy = pattern::find_rel( module_name.c_str(), "4D 33 C9 E8 ? ? ? ? 48 8B 85 ? ? ? ? 48 89 45 30", 42 );
			force_write<uint8_t>( name_str_addy, 0 );
		}

		resources_loaded = true;
	}

	const auto res = orig_LoadResource( hModule, hResInfo );

	for ( auto& resource : resources ) {
		if ( resource._rsrc == hResInfo ) {
			resource._mem = res;
			resource._size = orig_SizeofResource( hModule, hResInfo ); 
			break;
		}
	}

	return res;
}

// LockResource hook
LPVOID __stdcall hk_LockResource(
  HGLOBAL hResData
) {
	const auto res = orig_LockResource( hResData );

	for ( auto& resource : resources ) {
		if ( resource._mem == hResData ) {
			
			auto new_data = process_resource( res, resource._size );
			resource.new_size = new_data.size();

			const auto p = VirtualAlloc( NULL, new_data.size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
			
			memcpy( p, new_data.data(), new_data.size() );
			
			// FL will crash if the memory is not read-only
			DWORD old_protect;
			VirtualProtect( reinterpret_cast< LPVOID >( p ), new_data.size(), PAGE_READONLY, &old_protect );
			
			return p;

			break;
		}
	}

	return res;
}

// SizeofResource hook
DWORD __stdcall hk_SizeofResource(
  HMODULE hModule,
  HRSRC   hResInfo
) {
	const auto res = orig_SizeofResource( hModule, hResInfo );

	for ( auto& resource : resources ) {
		if ( resource._rsrc == hResInfo ) {
			return resource.new_size;
		}
	}

	return res;
}

template<typename T = std::string>
vec_byte_t read_file( T path ) {
	std::ifstream file( path, std::ios::binary | std::ios::ate );
	std::streamsize size = file.tellg();
	file.seekg( 0, std::ios::beg );

	auto buf = vec_byte_t( size );
	file.read( reinterpret_cast< char* >( buf.data() ), size );

	return buf;
}

bool replace( std::wstring& str, const std::wstring& from, const std::wstring& to ) {
	size_t start_pos = str.find( from );
	if ( start_pos == std::wstring::npos )
		return false;
	str.replace( start_pos, from.length(), to );
	return true;
}

void flip( uint32_t& val ) {
	uint32_t flipped = 0;
	flipped |= ( val & 0xFF ) << 16;
	flipped |= ( val & 0xFF00 );
	flipped |= ( val & 0xFF0000 ) >> 16;
	val = flipped;
};

col_replacement_t parse_col_kv( std::string key, nlohmann::json& value, bool flip_hex = false ) {
	col_replacement_t r;

	if ( key[ 0 ] == '#' ) {
		key = key.substr( 1 );
	}

	std::stringstream ss;
	ss << std::hex << key;
	ss >> r.a;

	ss.str( "" );
	ss.clear();

	auto val = value.get<std::string>();

	if ( val[ 0 ] == '#' ) {
		val = val.substr( 1 );
	}

	ss << std::hex << val;
	ss >> r.b;

	if ( flip_hex ) {
		flip( r.a );
		flip( r.b );
	}

	return r;
};

dfm_t parse_dfm( std::string key, nlohmann::json val ) {
	dfm_t dfm = {};

	dfm.obj_name = key;
	dfm.val_name = val[ "key" ].get<std::string>();
	dfm.no_create = val.contains( "noCreate" ) ? val[ "noCreate" ].get<bool>() : false;

	dfm::val v;

	const auto type = val[ "type" ].get<std::string>();

	if ( type == "hex32" ) {
		v.m_type = dfm::type_t::int32;
		
		uint32_t num_val;

		auto hex_val = val[ "value" ].get<std::string>();

		if ( hex_val[ 0 ] == '#' ) {
			hex_val = hex_val.substr( 1 );
		}

		std::stringstream ss;
		ss << std::hex << hex_val;
		ss >> num_val;

		flip( num_val );

		v.m_num_val = num_val;
	} else if ( type == "string" ) {
		v.m_type = dfm::type_t::string;
		v.m_str_val = val[ "value" ].get<std::string>();
	} else if ( type == "constant" ) {
		v.m_type = dfm::type_t::constant;
		v.m_str_val = val[ "value" ].get<std::string>();
	} else if ( type == "int32" ) {
		v.m_type = dfm::type_t::int32;
		v.m_num_val = val[ "value" ].get<int>();
	} else if ( type == "float" ) {
		v.m_type = dfm::type_t::long_double;
		
		auto val64 = val[ "value" ].get<double>();
		flt80 val80;

		_cvt64to80( &val64, &val80 );

		v.m_extended_val = val80;
	} else {
		throw std::exception( "Unsupported DFM value type!" );
	}

	dfm.v = v;

	if ( val.contains( "checkParent" ) ) {
		dfm.check_parent = true;
		dfm.parent_name = val[ "checkParent" ].get<std::string>();
	}

	return dfm;
}

std::string uncommentify( std::string json ) {
	// single line comments
	json = std::regex_replace( json, std::regex( R"(\/\/.*)" ), "" );
	// block comments
	json = std::regex_replace( json, std::regex( R"(\/\*(\*(?!\/)|[^*])*\*\/)" ), "" );

	return json;
}

void start() {
	//AllocConsole();
	//freopen( "CONOUT$", "w", stdout );

	char exe_path[ MAX_PATH ];
	GetModuleFileNameA( GetModuleHandle( "FL64.exe" ), exe_path, MAX_PATH );

	if ( fs::exists( fs::path( exe_path ).parent_path() / "_FLEngine_x64.dll" ) ) {
		module_name = "_FLEngine_x64.dll";
	}
	
	PWSTR path_tmp;
	auto get_folder_path_ret = SHGetKnownFolderPath( FOLDERID_RoamingAppData, 0, nullptr, &path_tmp );

	auto path = std::wstring( path_tmp );
	path += LR"(\flskinner\)";

	nlohmann::json j;

	std::string current_skin_file;

	try {
		const auto config_buffer = read_file( path + L"flskinner.json" );
		const auto config = uncommentify( std::string( config_buffer.begin(), config_buffer.end() ) );

		j = nlohmann::json::parse( config );

		current_skin_file = j[ "currentSkin" ].get<std::string>();

		path += LR"(skins\)";
		path += std::wstring( current_skin_file.begin(), current_skin_file.end() );
	} catch ( std::exception& e ) {
		std::stringstream err;
		err << "An exception occured when loading the config file (flskinner.json in %appdata%/flskinner)";
		err << std::endl;
		err << e.what();

		MessageBoxA( NULL, err.str().c_str(), "FLSkinner", MB_OK );
		exit( 1 );
	}

	nlohmann::json main_config = j;

	try {
		const auto skin_buffer = read_file( path );
		const auto skin = uncommentify( std::string( skin_buffer.begin(), skin_buffer.end() ) );

		j = nlohmann::json::parse( skin );

		for ( auto& item : j[ "dfmReplacements" ].items() ) {
			dfm_replacements.push_back( parse_col_kv( item.key(), item.value(), true ) );
		}

		for ( auto& item : j[ "hookReplacements" ].items() ) {
			hook_replacements.push_back( parse_col_kv( item.key(), item.value() ) );
		}

		// this will be deprecated
		for ( auto& item : j[ "dfm" ].items() ) {
			dfms.push_back( parse_dfm( item.key(), item.value() ) );
		}

		for ( auto& item : j[ "dfm2" ].items() ) {
			for ( auto& item2 : item.value().get<std::vector<nlohmann::json>>() ) {
				dfms.push_back( parse_dfm( item.key(), item2 ) );
			}
		}

		const auto setup_misc_val = [ &j ] ( std::string name, uint32_t& col, bool& toggle, bool should_flip = false ) {
			if ( j.contains( name ) ) {
				toggle = true;

				auto val = j[ name ].get<std::string>();

				if ( val[ 0 ] == '#' ) {
					val = val.substr( 1 );
				}

				std::stringstream ss;
				ss << std::hex << val;
				ss >> col;

				if ( should_flip ) flip( col );
			}
		};

		setup_misc_val( "mixerColor", mixer_color, replace_mixer_tracks, true );
		setup_misc_val( "gridColor", grid_color, replace_grid_color, true );
		setup_misc_val( "buttonColors", button_colors, replace_buttons, true );
		setup_misc_val( "browserColor", browser_color, replace_browser_color, true );
		setup_misc_val( "browserFilesColor", browser_files_color, replace_browser_files_color, true );

		setup_misc_val( "sequencerBlocks", sequencer_blocks, replace_sequencer_blocks, true );
		setup_misc_val( "sequencerBlocksHighlight", sequencer_blocks_highlight, replace_sequencer_blocks_highlight, true );
		setup_misc_val( "sequencerBlocksAlt", sequencer_blocks_alt, replace_sequencer_blocks_alt, true );
		setup_misc_val( "sequencerBlocksAltHighlight", sequencer_blocks_alt_highlight, replace_sequencer_blocks_alt_highlight, true );

		setup_misc_val( "defaultPatternColor", default_pattern_color, replace_default_pattern_color, true );
		setup_misc_val( "defaultPlaylistTrackColor", default_playlist_track_color, replace_default_playlist_track_color, true );

		setup_misc_val( "mixerLevelGradient1A", mixer_level_gradient1_a, replace_mixer_level_gradient, true );
		setup_misc_val( "mixerLevelGradient1B", mixer_level_gradient1_b, replace_mixer_level_gradient, true );
		setup_misc_val( "mixerLevelGradient2A", mixer_level_gradient2_a, replace_mixer_level_gradient, true );
		setup_misc_val( "mixerLevelGradient2B", mixer_level_gradient2_b, replace_mixer_level_gradient, true );
		setup_misc_val( "mixerLevelGradient3A", mixer_level_gradient3_a, replace_mixer_level_gradient, true );
		setup_misc_val( "mixerLevelGradient3B", mixer_level_gradient3_b, replace_mixer_level_gradient, true );
		setup_misc_val( "mixerLevelClipping", mixer_level_clipping, replace_mixer_level_gradient, true );

		setup_misc_val("mixerLevelBackgroundGradientA", mixer_level_background_gradient_a, replace_mixer_level_background_gradient, true);
		setup_misc_val("mixerLevelBackgroundGradientB", mixer_level_background_gradient_b, replace_mixer_level_background_gradient, true);

		setup_misc_val( "peakMeterGradientA", peak_meter_a, replace_peak_meter, true );
		setup_misc_val( "peakMeterGradientB", peak_meter_b, replace_peak_meter, true );
		setup_misc_val( "peakMeterGradientC", peak_meter_c, replace_peak_meter, true );
		

		if ( main_config.contains( "setDefaultPatternColor" ) && !main_config[ "setDefaultPatternColor" ].get<bool>() )
			replace_default_pattern_color = false;

		if ( main_config.contains( "setGridColors" ) && !main_config[ "setGridColors" ].get<bool>() )
			replace_grid_color = false;

		if ( main_config.contains( "setMixerColors" ) && !main_config[ "setMixerColors" ].get<bool>() )
			replace_mixer_tracks = false;

		if ( main_config.contains( "setPlaylistTrackColors" ) && !main_config[ "setPlaylistTrackColors" ].get<bool>() )
			replace_default_playlist_track_color = false;

		if ( main_config.contains( "hideName" ) && main_config[ "hideName" ].get<bool>() )
			hide_name = true;

	} catch ( std::exception& e ) {
		std::stringstream err;
		err << "An exception occured when loading the skin file (" << current_skin_file << ")";
		err << std::endl;
		err << e.what();

		MessageBoxA( NULL, err.str().c_str(), "FLSkinner", MB_OK );
		exit( 1 );
	}

	MH_Initialize();
	MH_CreateHook( &LoadResource, &hk_LoadResource, reinterpret_cast< void** >( &orig_LoadResource ) );
	MH_EnableHook( &LoadResource );
	MH_CreateHook( &LockResource, &hk_LockResource, reinterpret_cast< void** >( &orig_LockResource ) );
	MH_EnableHook( &LockResource );
	MH_CreateHook( &SizeofResource, &hk_SizeofResource, reinterpret_cast< void** >( &orig_SizeofResource ) );
	MH_EnableHook( &SizeofResource );
}

BOOL WINAPI DllMain(
  _In_ HINSTANCE hinstDLL,
  _In_ DWORD     fdwReason,
  _In_ LPVOID    lpvReserved
) {
	switch ( fdwReason ) {
	case DLL_PROCESS_ATTACH:
		start();
		break;
	}

	return TRUE;
}