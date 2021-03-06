#include <main.hpp>
#include <netfilter.hpp>
#include <GarrysMod/Lua/Interface.h>
#include <scanning/symbolfinder.hpp>
#include <iserver.h>
#include <Platform.hpp>


Symbol::Symbol( const std::string &nam, size_t len ) :
	name( nam ), length( len ) { }

Symbol Symbol::FromSignature( const std::string &signature )
{
	return Symbol( signature, signature.size( ) );
}

Symbol Symbol::FromName( const std::string &name )
{
	return Symbol( "@" + name );
}


#if defined __APPLE__

#include <AvailabilityMacros.h>

#if MAC_OS_X_VERSION_MIN_REQUIRED > 1050

#error The only supported compilation platform for this project on Mac OS X is GCC with Mac OS X 10.5 SDK (for ABI reasons).

#endif

#endif


namespace global
{

#if defined SYSTEM_WINDOWS

	static const std::string CGameServer_sym = "?sv@@3VCGameServer@@A";
	static const Symbol IServer_sym = Symbol::FromSignature( "\x2A\x2A\x2A\x2A\xE8\x2A\x2A\x2A\x2A\xD8\x6D\x24\x83\x4D\xEC\x10" );

#elif defined SYSTEM_POSIX

	static const std::string CGameServer_sym = "sv";
	static const Symbol IServer_sym = Symbol::FromName( "sv" );

#endif

	SourceSDK::FactoryLoader engine_loader( "engine" );
	IServer *server = nullptr;


	static void PreInitialize( GarrysMod::Lua::ILuaBase *LUA )
	{
		{
			SymbolFinder symfinder;

			server = reinterpret_cast<IServer *>(
				engine_loader.GetSymbol( CGameServer_sym )
			);
			if( server == nullptr )
			{
				void *temp_server = symfinder.Resolve(
					engine_loader.GetModule( ),
					IServer_sym.name.c_str( ),
					IServer_sym.length
				);
				if( temp_server == nullptr )
					LUA->ThrowError( "failed to locate IServer" );

				server =

#if defined SYSTEM_POSIX

					reinterpret_cast<IServer *>

#else

					*reinterpret_cast<IServer **>

#endif

					( temp_server );
			}
		}

	if( server == nullptr )
			LUA->ThrowError( "failed to dereference IServer" );

		LUA->CreateTable( );

		LUA->PushString( "Query 1.1" );
		LUA->SetField( -2, "Version" );

		// version num follows LuaJIT style, xxyyzz
		LUA->PushNumber( 010000 );
		LUA->SetField( -2, "VersionNum" );
	}

	static void Initialize( GarrysMod::Lua::ILuaBase *LUA )
	{
		LUA->SetField( GarrysMod::Lua::INDEX_GLOBAL, "query" );
	}

	static void Deinitialize( GarrysMod::Lua::ILuaBase *LUA )
	{
		LUA->PushNil( );
		LUA->SetField( GarrysMod::Lua::INDEX_GLOBAL, "query" );
	}

}

GMOD_MODULE_OPEN( )
{
	global::PreInitialize( LUA );
	netfilter::Initialize( LUA );
	global::Initialize( LUA );
	return 1;
}

GMOD_MODULE_CLOSE( )
{
	netfilter::Deinitialize( LUA );
	global::Deinitialize( LUA );
	return 0;
}
