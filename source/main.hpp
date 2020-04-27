#pragma once

#include <string>
#include <GarrysMod/Interfaces.hpp>

//#if defined DEBUG

#include <dbg.h>
#include <Color.h>

static Color __yellow( 255, 255, 0, 255 );
#define DebugMsg( ... ) Msg( __VA_ARGS__ )
#define DebugWarning( ... ) ConColorMsg( 1, __yellow, __VA_ARGS__ )

#if defined DEBUG//#else

#define DebugMsg( arg, ... ) (void)arg
#define DebugWarning( arg, ... ) (void)arg

#endif

class IServer;

struct Symbol
{
	std::string name;
	size_t length;

	Symbol( const std::string &nam, size_t len = 0 );

	static Symbol FromSignature( const std::string &signature );
	static Symbol FromName( const std::string &name );
};

namespace global
{
	extern SourceSDK::FactoryLoader engine_loader;
	extern IServer *server;

}
