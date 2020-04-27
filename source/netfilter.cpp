#include <netfilter.hpp>
#include <main.hpp>
#include <GarrysMod/Lua/Interface.h>
#include <GarrysMod/Lua/LuaInterface.h>
#include <GarrysMod/Interfaces.hpp>
#include <stdint.h>
#include <stddef.h>
#include <set>
#include <queue>
#include <string>
#include <eiface.h>
#include <filesystem_stdio.h>
#include <iserver.h>
#include <iclient.h>
#include <inetchannel.h>
#include <inetchannelinfo.h>
#include "cdll_int.h"
#include <threadtools.h>
#include <utlvector.h>
#include <bitbuf.h>
#include <steam/steam_gameserver.h>
#include <game/server/iplayerinfo.h>
#include <scanning/symbolfinder.hpp>
#include <Platform.hpp>

#if defined _WIN32

#include <winsock2.h>
#include <unordered_set>
#define strtoll _strtoi64

typedef std::unordered_set<uint32_t> set_uint32;

#elif defined __linux

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unordered_set>

typedef std::unordered_set<uint32_t> set_uint32;

#elif defined __APPLE__

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

typedef std::set<uint32_t> set_uint32;

#endif

namespace netfilter
{

	typedef int32_t(*Hook_recvfrom_t)(
		int32_t s,
		char *buf,
		int32_t buflen,
		int32_t flags,
		sockaddr *from,
		int32_t *fromlen
		);

	struct packet_t
	{
		packet_t() :
			address_size(sizeof(address))
		{ }

		sockaddr_in address;
		int32_t address_size;
		std::vector<char> buffer;
	};

	struct netsocket_t
	{
		int32_t nPort;
		bool bListening;
		int32_t hUDP;
		int32_t hTCP;
	};

	struct reply_info_t
	{
		bool dontsend;

		std::string game_name;
		std::string map_name;
		std::string game_dir;
		std::string gamemode_name;
		int32_t amt_clients;
		int32_t max_clients;
		int32_t amt_bots;
		char server_type;
		char os_type;
		bool passworded;
		bool secure;
		std::string game_version;
		int32_t udp_port;
		std::string tags;
		int appid;
		uint64_t steamid;
	};

	struct gamemode_t
	{
		bool _unk1;
		bool _unk2;
		uint16_t _pad;
		std::string name;
		std::string path;
		std::string filters;
		std::string base;
		std::string workshopid;
	};

	struct query_client_t
	{
		bool operator<(const query_client_t &rhs) const
		{
			return address < rhs.address;
		}

		bool operator==(const query_client_t &rhs) const
		{
			return address == rhs.address;
		}

		uint32_t address;
		uint32_t last_reset;
		uint32_t count;
	};
	
	struct player_t
	{
		byte index;
		std::string name;
		double score;
		double time;

	};

	struct reply_player_t
	{
		bool dontsend;
		bool senddefault;

		byte count;
		std::vector<player_t> players;
	};

	enum PacketType
	{
		PacketTypeInvalid = -1,
		PacketTypeGood,
		PacketTypeInfo,
		PacketTypePlayer,
	};
	
	class CSteamGameServerAPIContext
	{
	public:
		ISteamClient *m_pSteamClient;
		ISteamGameServer *m_pSteamGameServer;
		ISteamUtils *m_pSteamGameServerUtils;
		ISteamNetworking *m_pSteamGameServerNetworking;
		ISteamGameServerStats *m_pSteamGameServerStats;
		ISteamHTTP *m_pSteamHTTP;
		ISteamInventory *m_pSteamInventory;
		ISteamUGC *m_pSteamUGC;
		ISteamApps *m_pSteamApps;
	};

	typedef CUtlVector<netsocket_t> netsockets_t;

#if defined SYSTEM_WINDOWS

	static const std::vector<Symbol> FileSystemFactory_syms = {
		Symbol::FromName( "?FileSystemFactory@@YAPEAXPEBDPEAH@Z" ),
		Symbol::FromSignature( "\x55\x8B\xEC\x68\x2A\x2A\x2A\x2A\xFF\x75\x08\xE8" )
	};

	static const Symbol g_pFullFileSystem_sym = Symbol::FromName( "g_pFullFileSystem" );

	static const std::string GetNetSocket_sym = "?GMOD_GetNetSocket@@YAPEAUnetsocket_t@@H@Z";
	static const Symbol net_sockets_sym = Symbol::FromSignature(
		"\x2A\x2A\x2A\x2A\x56\x57\x8B\x7D\x08\x8B\xF7\x03\xF6\x8B\x44\xF3\x0C\x85\xC0\x74\x0A\x57\x50" );

	static constexpr char operating_system_char = 'w';

#elif defined SYSTEM_POSIX

	static const std::vector<Symbol> FileSystemFactory_syms = { Symbol::FromName( "_Z17FileSystemFactoryPKcPi" ) };

	static const Symbol g_pFullFileSystem_sym = Symbol::FromName( "g_pFullFileSystem" );

	static const std::string GetNetSocket_sym = "_Z17GMOD_GetNetSocketi";
	static const Symbol net_sockets_sym = Symbol::FromName( "_ZL11net_sockets" );

#if defined SYSTEM_LINUX

	static constexpr char operating_system_char = 'l';

#elif defined SYSTEM_MACOSX

	static constexpr char operating_system_char = 'm';

#endif

#endif



	static SourceSDK::ModuleLoader dedicated_loader( "dedicated" );
	static SourceSDK::FactoryLoader server_loader( "server" );

	static CSteamGameServerAPIContext gameserver_context;
	static bool gameserver_context_initialized = false;

	
	static Hook_recvfrom_t Hook_recvfrom = VCRHook_recvfrom;
	static int32_t game_socket = -1;

	static const char *default_game_version = "2019.11.12"; // 16.12.01
	static const uint8_t default_proto_version = 17;
	static bool info_cache_enabled = true;
	static reply_info_t reply_info;
	static char info_cache_buffer[1024] = { 0 };
	static bf_write info_cache_packet(info_cache_buffer, sizeof(info_cache_buffer));
	static uint32_t info_cache_last_update = 0;
	static uint32_t info_cache_time = 5;

	static reply_player_t reply_player;
	static char player_cache_buffer[1024] = { 0 };
	static bf_write player_cache_packet(player_cache_buffer, sizeof(player_cache_buffer));

	static IPlayerInfoManager *playerinfo = nullptr;
	static CGlobalVars *globalvars = nullptr;
	static IServerGameDLL *gamedll = nullptr;
	static IVEngineServer *engine_server = nullptr;
	static IFileSystem *filesystem = nullptr;
	static GarrysMod::Lua::ILuaInterface *lua = nullptr;

	static void BuildStaticReplyInfo()
	{
		reply_info.gamemode_name = gamedll->GetGameDescription();

		{
			reply_info.game_dir.resize(256);
			engine_server->GetGameDir(&reply_info.game_dir[0], reply_info.game_dir.size());
			reply_info.game_dir.resize(strlen(reply_info.game_dir.c_str()));

			size_t pos = reply_info.game_dir.find_last_of("\\/");
			if (pos != reply_info.game_dir.npos)
				reply_info.game_dir.erase(0, pos + 1);
		}

		reply_info.max_clients = global::server->GetMaxClients();
		reply_info.udp_port = global::server->GetUDPPort();

		{
			const IGamemodeSystem::Information &gamemode =
				static_cast<CFileSystem_Stdio *>(filesystem)->Gamemodes()->Active();

			reply_info.tags = " gm:";
			reply_info.tags += gamemode.name;

			if (!gamemode.workshopid.empty())
			{
				reply_info.tags += " gmws:";
				reply_info.tags += gamemode.workshopid;
			}
		}

		{
			FileHandle_t file = filesystem->Open("steam.inf", "r", "GAME");
			if (file == nullptr)
			{
				reply_info.game_version = default_game_version;
				DebugWarning("[Query] Error opening steam.inf\n");
				return;
			}

			char buff[256] = { 0 };
			bool failed = filesystem->ReadLine(buff, sizeof(buff), file) == nullptr;
			filesystem->Close(file);
			if (failed)
			{
				reply_info.game_version = default_game_version;
				DebugWarning("[Query] Failed reading steam.inf\n");
				return;
			}

			reply_info.game_version = &buff[13];

			size_t pos = reply_info.game_version.find_first_of("\r\n");
			if (pos != reply_info.game_version.npos)
				reply_info.game_version.erase(pos);
		}

		reply_info.os_type = operating_system_char;
		reply_info.server_type = 'd';
	}

	static void UpdateReplyInfo()
	{
		reply_info.game_name = global::server->GetName();
		reply_info.map_name = global::server->GetMapName();
		reply_info.gamemode_name = gamedll->GetGameDescription();
		reply_info.appid = engine_global::server->GetAppID();
		reply_info.amt_clients = global::server->GetNumClients();
		reply_info.amt_bots = global::server->GetNumFakeClients();
		reply_info.passworded = global::server->GetPassword() != nullptr ? 1 : 0;
		
		if( !gameserver_context_initialized )
			gameserver_context_initialized = gameserver_context.Init( );



		bool reply_info.secure = false;
		if( gameserver_context_initialized )
		{
			ISteamGameServer *steamGS = gameserver_context.SteamGameServer( );
			if( steamGS != nullptr )
				reply_info.secure = steamGS->BSecure( );
		}

		const CSteamID *sid = engine_global::server->GetGameServerSteamID();
		if (sid != nullptr)
			reply_info.steamid = sid->ConvertToUint64();
	}

	// maybe divide into low priority and high priority data?
	// low priority would be VAC protection status for example
	// updated on a much bigger period
	static void BuildReplyInfoPacket(reply_info_t info)
	{
		info_cache_packet.Reset();

		info_cache_packet.WriteLong(-1); // connectionless packet header
		info_cache_packet.WriteByte('I'); // packet type is always 'I'
		info_cache_packet.WriteByte(default_proto_version);

		info_cache_packet.WriteString(info.game_name.c_str());
		info_cache_packet.WriteString(info.map_name.c_str());
		info_cache_packet.WriteString(info.game_dir.c_str());
		info_cache_packet.WriteString(info.gamemode_name.c_str());

		info_cache_packet.WriteShort(info.appid);

		info_cache_packet.WriteByte(info.amt_clients);
		info_cache_packet.WriteByte(info.max_clients);
		info_cache_packet.WriteByte(info.amt_bots);
		info_cache_packet.WriteByte(info.server_type);
		info_cache_packet.WriteByte(info.os_type);
		info_cache_packet.WriteByte(info.passworded);

		// if vac protected, it activates itself some time after startup
		info_cache_packet.WriteByte(info.secure);
		info_cache_packet.WriteString(info.game_version.c_str());
		
		bool notags = info.tags.empty();
		// 0x80 - port number is present
		// 0x10 - server steamid is present
		// 0x20 - tags are present
		// 0x01 - game long appid is present
		info_cache_packet.WriteByte(0x80 | 0x10 | (notags ? 0x00 : 0x20) | 0x01);
		info_cache_packet.WriteShort(info.udp_port);
		info_cache_packet.WriteLongLong(info.steamid);
		if (!notags)
			info_cache_packet.WriteString(info.tags.c_str());
		info_cache_packet.WriteLongLong(info.appid);
	}

	reply_info_t CallInfoHook(const sockaddr_in &from)
	{
		char hook[] = "A2S_INFO";

		lua->GetField(GarrysMod::Lua::INDEX_GLOBAL, "hook");
		if (!lua->IsType(-1, GarrysMod::Lua::Type::TABLE))
		{
			lua->ErrorNoHalt("[%s] Global hook is not a table!\n", hook);
			lua->Pop(2);
			return reply_info;
		}

		lua->GetField(-1, "Run");
		lua->Remove(-2);
		if (!lua->IsType(-1, GarrysMod::Lua::Type::FUNCTION))
		{
			lua->ErrorNoHalt("[%s] Global hook.Run is not a function!\n", hook);
			lua->Pop(2);
			return reply_info;
		}

		lua->PushString(hook);
		lua->PushString(inet_ntoa(from.sin_addr));
		lua->PushNumber(27015);

		lua->CreateTable();

		lua->PushString(reply_info.game_name.c_str());
		lua->SetField(-2, "name");

		lua->PushString(reply_info.map_name.c_str());
		lua->SetField(-2, "map");

		lua->PushString(reply_info.game_dir.c_str());
		lua->SetField(-2, "folder");

		lua->PushString(reply_info.gamemode_name.c_str());
		lua->SetField(-2, "gamemode");

		lua->PushNumber(reply_info.amt_clients);
		lua->SetField(-2, "players");

		lua->PushNumber(reply_info.max_clients);
		lua->SetField(-2, "maxplayers");

		lua->PushNumber(reply_info.amt_bots);
		lua->SetField(-2, "bots");

		lua->PushString(&reply_info.server_type);
		lua->SetField(-2, "servertype");

		lua->PushString(&reply_info.os_type);
		lua->SetField(-2, "os");

		lua->PushBool(reply_info.passworded);
		lua->SetField(-2, "passworded");

		lua->PushBool(reply_info.secure);
		lua->SetField(-2, "VAC");

		lua->PushNumber(reply_info.udp_port);
		lua->SetField(-2, "gameport");

		std::string steamid = std::to_string(reply_info.steamid);
		lua->PushString(steamid.c_str());
		lua->SetField(-2, "steamid");

		lua->PushString(reply_info.tags.c_str());
		lua->SetField(-2, "tags");

		if (lua->PCall(4, 1, 0) != 0)
			lua->ErrorNoHalt("\n[%s] %s\n\n", hook, lua->GetString(-1));

		reply_info_t newreply;
		newreply.dontsend = false;

		newreply.game_name = reply_info.game_name;
		newreply.map_name = reply_info.map_name;
		newreply.game_dir = reply_info.game_dir;
		newreply.gamemode_name = reply_info.gamemode_name;
		newreply.amt_clients = reply_info.amt_clients;
		newreply.max_clients = reply_info.max_clients;
		newreply.amt_bots = reply_info.amt_bots;
		newreply.server_type = reply_info.server_type;
		newreply.os_type = reply_info.os_type;
		newreply.passworded = reply_info.passworded;
		newreply.secure = reply_info.secure;
		newreply.game_version = reply_info.game_version;
		newreply.udp_port = reply_info.udp_port;
		newreply.tags = reply_info.tags;
		newreply.appid = reply_info.appid;
		newreply.steamid = reply_info.steamid;

		if (lua->IsType(-1, GarrysMod::Lua::Type::BOOL))
		{
			if (lua->GetBool(-1))
			{
				newreply = reply_info; // return default when return true
			}
			else
			{
				newreply.dontsend = true; // dont send when return false
			}
		}
		else if (lua->IsType(-1, GarrysMod::Lua::Type::TABLE))
		{
			lua->GetField(-1, "name");
			newreply.game_name = lua->GetString(-1);
			lua->Pop(1);

			lua->GetField(-1, "map");
			newreply.map_name = lua->GetString(-1);
			lua->Pop(1);

			lua->GetField(-1, "folder");
			newreply.game_dir = lua->GetString(-1);
			lua->Pop(1);

			lua->GetField(-1, "gamemode");
			newreply.gamemode_name = lua->GetString(-1);
			lua->Pop(1);

			lua->GetField(-1, "players");
			newreply.amt_clients = lua->GetNumber(-1);
			lua->Pop(1);

			lua->GetField(-1, "maxplayers");
			newreply.max_clients = lua->GetNumber(-1);
			lua->Pop(1);

			lua->GetField(-1, "bots");
			newreply.amt_bots = lua->GetNumber(-1);
			lua->Pop(1);

			lua->GetField(-1, "servertype");
			newreply.server_type = lua->GetString(-1)[0]; //make into char
			lua->Pop(1);

			lua->GetField(-1, "os");
			newreply.os_type = lua->GetString(-1)[0];
			lua->Pop(1);

			lua->GetField(-1, "passworded");
			newreply.passworded = lua->GetBool(-1);
			lua->Pop(1);

			lua->GetField(-1, "VAC");
			newreply.secure = lua->GetBool(-1);
			lua->Pop(1);

			lua->GetField(-1, "gameport");
			newreply.udp_port = lua->GetNumber(-1);
			lua->Pop(1);

			lua->GetField(-1, "steamid");
			newreply.steamid = strtoll(lua->GetString(-1), 0, 10);
			lua->Pop(1);

			lua->GetField(-1, "tags");
			newreply.tags = lua->GetString(-1);
			lua->Pop(1);
		}

		lua->Pop(1);

		return newreply;
	}

	inline PacketType SendInfoCache(const sockaddr_in &from, uint32_t time)
	{
		if (time - info_cache_last_update >= info_cache_time)
		{
			UpdateReplyInfo();
			info_cache_last_update = time;
		}

		reply_info_t info = CallInfoHook(from);
		if (info.dontsend)
			return PacketTypeInvalid; // dont send it

		BuildReplyInfoPacket(info);

		sendto(
			game_socket,
			reinterpret_cast<char *>(info_cache_packet.GetData()),
			info_cache_packet.GetNumBytesWritten(),
			0,
			reinterpret_cast<const sockaddr *>(&from),
			sizeof(from)
			);

		return PacketTypeInvalid; // we've handled it
	}

	static PacketType HandleInfoQuery(const sockaddr_in &from)
	{
		uint32_t time = static_cast<uint32_t>(globalvars->realtime);

		if (info_cache_enabled)
			return SendInfoCache(from, time);

		return PacketTypeGood;
	}

	static void BuildReplyPlayerPacket(reply_player_t r_player)
	{
		player_cache_packet.Reset();

		player_cache_packet.WriteLong(-1); // connectionless packet header
		player_cache_packet.WriteByte('D'); // packet type is always 'I'

		player_cache_packet.WriteByte(r_player.count);
		for (int i = 0; i < r_player.count; i++)
		{
			player_t player = r_player.players[i];
			player_cache_packet.WriteByte(i);
			player_cache_packet.WriteString(player.name.c_str());
			player_cache_packet.WriteLong(player.score);
			player_cache_packet.WriteFloat(player.time);
		}

	}

	static reply_player_t CallPlayerHook(const sockaddr_in &from)
	{
		reply_player_t newreply;
		newreply.dontsend = false;
		newreply.senddefault = true;


		char hook[] = "A2S_PLAYER";

		lua->GetField(GarrysMod::Lua::INDEX_GLOBAL, "hook");
		if (!lua->IsType(-1, GarrysMod::Lua::Type::TABLE))
		{
			lua->ErrorNoHalt("[%s] Global hook is not a table!\n", hook);
			lua->Pop(2);
			return newreply;
		}

		lua->GetField(-1, "Run");
		lua->Remove(-2);
		if (!lua->IsType(-1, GarrysMod::Lua::Type::FUNCTION))
		{
			lua->ErrorNoHalt("[%s] Global hook.Run is not a function!\n", hook);
			lua->Pop(2);
			return newreply;
		}

		lua->PushString(hook);
		lua->PushString(inet_ntoa(from.sin_addr));
		lua->PushNumber(27015);

		if (lua->PCall(3, 1, 0) != 0)
			lua->ErrorNoHalt("\n[%s] %s\n\n", hook, lua->GetString(-1));
		
		if (lua->IsType(-1, GarrysMod::Lua::Type::BOOL))
		{
			if (!lua->GetBool(-1))
			{
				newreply.senddefault = false;
				newreply.dontsend = true; // dont send when return false
			}
		}
		else if (lua->IsType(-1, GarrysMod::Lua::Type::TABLE))
		{
			newreply.senddefault = false;

			int count = lua->ObjLen(-1);
			newreply.count = count;
			
			std::vector<player_t> newPlayers(count);

			for (int i = 0; i < count; i++)
			{
				player_t newPlayer;
				newPlayer.index = i;

				lua->PushNumber(i + 1);
				lua->GetTable(-2);

				lua->GetField(-1, "name");
				newPlayer.name = lua->GetString(-1);
				lua->Pop(1);

				lua->GetField(-1, "score");
				newPlayer.score = lua->GetNumber(-1);
				lua->Pop(1);

				lua->GetField(-1, "time");
				newPlayer.time = lua->GetNumber(-1);
				lua->Pop(1);				

				lua->Pop(1);
				newPlayers.at(i) = newPlayer;
			}

			newreply.players = newPlayers;
		}

		lua->Pop(1);

		return newreply;
	}

	static PacketType HandlePlayerQuery(const sockaddr_in &from)
	{
		reply_player_t player = CallPlayerHook(from);

		if (player.senddefault)
			return PacketTypeGood;

		if (player.dontsend)
			return PacketTypeInvalid; // dont senkd it

		BuildReplyPlayerPacket(player);

		sendto(
			game_socket,
			reinterpret_cast<char *>(player_cache_packet.GetData()),
			player_cache_packet.GetNumBytesWritten(),
			0,
			reinterpret_cast<const sockaddr *>(&from),
			sizeof(from)
		);

		return PacketTypeInvalid; // we've handled it
	}

	static PacketType ClassifyPacket(const char *data, int32_t len, const sockaddr_in &from)
	{
		if (len == 0)
		{
			DebugWarning(
				"[Query] Bad OOB! len: %d from %s\n",
				len,
				inet_ntoa(from.sin_addr)
			);
			return PacketTypeInvalid;
		}

		if (len < 5)
			return PacketTypeGood;

		int32_t channel = *reinterpret_cast<const int32_t *>(data);
		if (channel == -2)
		{
			DebugWarning(
				"[Query] Bad OOB! len: %d, channel: 0x%X from %s\n",
				len,
				channel,
				inet_ntoa(from.sin_addr)
			);
			return PacketTypeInvalid;
		}

		if (channel != -1)
			return PacketTypeGood;

		int challenge = *reinterpret_cast<const int *>(data + 5);
		if (challenge == -1)
			return PacketTypeGood; // default challenge response

		uint8_t type = *reinterpret_cast<const uint8_t *>(data + 4);
		if (type == 'T')
			return PacketTypeInfo;
		if (type == 'U')
			return PacketTypePlayer;
		if (type == 'W')
			return PacketTypeGood;// default challenge response

		return PacketTypeGood;
	}

	inline int32_t HandleNetError(int32_t value)
	{
		if (value == -1)

#if defined SYSTEM_WINDOWS

			WSASetLastError(WSAEWOULDBLOCK);

#elif defined SYSTEM_POSIX

			errno = EWOULDBLOCK;

#endif

		return value;
	}

	inline int32_t ReceiveAndAnalyzePacket(
		int32_t s,
		char *buf,
		int32_t buflen,
		int32_t flags,
		sockaddr *from,
		int32_t *fromlen
		)
	{
		sockaddr_in &infrom = *reinterpret_cast<sockaddr_in *>(from);
		int32_t len = Hook_recvfrom(s, buf, buflen, flags, from, fromlen);
		if (len == -1)
			return -1;

		PacketType type = ClassifyPacket(buf, len, infrom);
		if (type == PacketTypeInfo)
			type = HandleInfoQuery(infrom);

		if (type == PacketTypePlayer)
			type = HandlePlayerQuery(infrom);

		if (type == PacketTypeInvalid)
			return -1;

		return len;
	}

	static int32_t Hook_recvfrom_d(
		int32_t s,
		char *buf,
		int32_t buflen,
		int32_t flags,
		sockaddr *from,
		int32_t *fromlen
		)
	{
		return HandleNetError(ReceiveAndAnalyzePacket(s, buf, buflen, flags, from, fromlen));
	}

	inline void SetDetourStatus(bool enabled)
	{
		if (enabled)
			VCRHook_recvfrom = Hook_recvfrom_d;
		else
			VCRHook_recvfrom = Hook_recvfrom;
	}


	LUA_FUNCTION_STATIC(EnableInfoDetour)
	{
		LUA->CheckType(1, GarrysMod::Lua::Type::BOOL);
		SetDetourStatus(LUA->GetBool(1));
		return 0;
	}

	void Initialize(GarrysMod::Lua::ILuaBase *LUA)
	{
		lua = static_cast<GarrysMod::Lua::ILuaInterface *>(LUA);

		if( !server_loader.IsValid( ) )
			LUA->ThrowError( "unable to get server factory" );


		gamedll = server_loader.GetInterface<IServerGameDLL>( INTERFACEVERSION_SERVERGAMEDLL );
		if (gamedll == nullptr)
			LUA->ThrowError("failed to load required IServerGameDLL interface");

		engine_server = global::engine_loader.GetInterface<IVEngineServer>(
			INTERFACEVERSION_VENGINESERVER
		);
		if (engine_server == nullptr)
			LUA->ThrowError("failed to load required IVEngineServer interface");

		playerinfo = server_loader.GetInterface<IPlayerInfoManager>(INTERFACEVERSION_PLAYERINFOMANAGER);
		if (playerinfo == nullptr)
			LUA->ThrowError("failed to load required IPlayerInfoManager interface");

		globalvars = playerinfo->GetGlobalVars();
		if (globalvars == nullptr)
			LUA->ThrowError("failed to load required CGlobalVars interface");

		{
		SymbolFinder symfinder;

		CreateInterfaceFn factory = nullptr;

		for( const auto &symbol : FileSystemFactory_syms )
			{
				factory = reinterpret_cast<CreateInterfaceFn>( symfinder.Resolve(
					dedicated_loader.GetModule( ),
					symbol.name.c_str( ),
					symbol.length
				) );
				if( factory != nullptr )
					break;
			}

		if( factory == nullptr )
			{
				IFileSystem **filesystem_ptr =
					reinterpret_cast<IFileSystem **>( symfinder.Resolve(
						dedicated_loader.GetModule( ),
						g_pFullFileSystem_sym.name.c_str( ),
						g_pFullFileSystem_sym.length
					) );
				if( filesystem_ptr == nullptr )
					filesystem_ptr =
					reinterpret_cast<IFileSystem **>( symfinder.Resolve(
						server_loader.GetModule( ),
						g_pFullFileSystem_sym.name.c_str( ),
						g_pFullFileSystem_sym.length
					) );

				if( filesystem_ptr != nullptr )
					filesystem = *filesystem_ptr;
			}
			else
			{
				filesystem =
					static_cast<IFileSystem *>( factory( FILESYSTEM_INTERFACE_VERSION, nullptr ) );
			}

		if (filesystem == nullptr)
			LUA->ThrowError("failed to initialize IFileSystem");
		



		auto GetNetSocket = reinterpret_cast<GetNetSocket_t>(
						global::engine_loader.GetSymbol( GetNetSocket_sym )
					);

		if( GetNetSocket != nullptr )
					{
						netsocket_t *socket = GetNetSocket( 1 );
						if( socket != nullptr )
							game_socket = socket->hUDP;
					}


			if( game_socket == INVALID_SOCKET )
			{
				void *temp_net_sockets = reinterpret_cast<CSteamGameServerAPIContext *>( symfinder.Resolve(
					global::engine_loader.GetModule( ),
					net_sockets_sym.name.c_str( ),
					net_sockets_sym.length
				) );
				if( temp_net_sockets != nullptr )
				{
					netsockets_t *net_sockets =

#if defined SYSTEM_POSIX

						reinterpret_cast<netsockets_t *>

#else

						*reinterpret_cast<netsockets_t **>

#endif

						( temp_net_sockets );
					if( net_sockets != nullptr )
						game_socket = net_sockets->Element( 1 ).hUDP;
				}
			}
		}

		if (game_socket == -1)
			LUA->ThrowError("got an invalid server socket");

		BuildStaticReplyInfo();

		LUA->PushCFunction(EnableInfoDetour);
		LUA->SetField(-2, "EnableInfoDetour");
	}

	void Deinitialize(GarrysMod::Lua::ILuaBase *)
	{
		VCRHook_recvfrom = Hook_recvfrom;
	}
}
