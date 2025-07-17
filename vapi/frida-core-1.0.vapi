[CCode (cheader_filename = "frida-core.h", cprefix = "Frida", lower_case_cprefix = "frida_")]
namespace Frida {
	public static void init ();
	public static void shutdown ();
	public static void deinit ();
	public static unowned GLib.MainContext get_main_context ();

	public sealed class DeviceManager : GLib.Object {
		public DeviceManager ();

		public async void close (GLib.Cancellable? cancellable = null) throws GLib.IOError;
		public void close_sync (GLib.Cancellable? cancellable = null) throws GLib.IOError;
		public async Frida.Device get_device_by_id (string id, int timeout = 0, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.Device get_device_by_id_sync (string id, int timeout = 0, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.Device get_device_by_type (Frida.DeviceType type, int timeout = 0, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.Device get_device_by_type_sync (Frida.DeviceType type, int timeout = 0, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.Device get_device (Frida.DeviceManager.Predicate predicate, int timeout = 0, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.Device get_device_sync (Frida.DeviceManager.Predicate predicate, int timeout = 0, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.Device? find_device_by_id (string id, int timeout = 0, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.Device? find_device_by_id_sync (string id, int timeout = 0, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.Device? find_device_by_type (Frida.DeviceType type, int timeout = 0, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.Device? find_device_by_type_sync (Frida.DeviceType type, int timeout = 0, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.Device? find_device (Frida.DeviceManager.Predicate predicate, int timeout = 0, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.Device? find_device_sync (Frida.DeviceManager.Predicate predicate, int timeout = 0, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.DeviceList enumerate_devices (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.DeviceList enumerate_devices_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.Device add_remote_device (string address, Frida.RemoteDeviceOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.Device add_remote_device_sync (string address, Frida.RemoteDeviceOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async void remove_remote_device (string address, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void remove_remote_device_sync (string address, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public delegate bool Predicate (Frida.Device device);
		public DeviceManager.with_nonlocal_backends_only ();
		public DeviceManager.with_socket_backend_only ();

		public signal void added (Frida.Device device);
		public signal void changed ();
		public signal void removed (Frida.Device device);
	}

	public sealed class DeviceList : GLib.Object {
		public int size ();
		public new Frida.Device @get (int index);
	}

	public sealed class Device : GLib.Object {
		public string id { get; }
		public string name { get; }
		public GLib.Variant? icon { get; construct; }
		public Frida.DeviceType dtype { get; }
		public Frida.Bus bus { get; }

		public bool is_lost ();
		public async GLib.HashTable<string,GLib.Variant> query_system_parameters (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public GLib.HashTable<string,GLib.Variant> query_system_parameters_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.Application? get_frontmost_application (Frida.FrontmostQueryOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.Application? get_frontmost_application_sync (Frida.FrontmostQueryOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.ApplicationList enumerate_applications (Frida.ApplicationQueryOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.ApplicationList enumerate_applications_sync (Frida.ApplicationQueryOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.Process get_process_by_pid (uint pid, Frida.ProcessMatchOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.Process get_process_by_pid_sync (uint pid, Frida.ProcessMatchOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.Process get_process_by_name (string name, Frida.ProcessMatchOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.Process get_process_by_name_sync (string name, Frida.ProcessMatchOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.Process get_process (Frida.Device.ProcessPredicate predicate, Frida.ProcessMatchOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.Process get_process_sync (Frida.Device.ProcessPredicate predicate, Frida.ProcessMatchOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.Process? find_process_by_pid (uint pid, Frida.ProcessMatchOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.Process? find_process_by_pid_sync (uint pid, Frida.ProcessMatchOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.Process? find_process_by_name (string name, Frida.ProcessMatchOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.Process? find_process_by_name_sync (string name, Frida.ProcessMatchOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.Process? find_process (Frida.Device.ProcessPredicate predicate, Frida.ProcessMatchOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.Process? find_process_sync (Frida.Device.ProcessPredicate predicate, Frida.ProcessMatchOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.ProcessList enumerate_processes (Frida.ProcessQueryOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.ProcessList enumerate_processes_sync (Frida.ProcessQueryOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async void enable_spawn_gating (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void enable_spawn_gating_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async void disable_spawn_gating (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void disable_spawn_gating_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.SpawnList enumerate_pending_spawn (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.SpawnList enumerate_pending_spawn_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.ChildList enumerate_pending_children (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.ChildList enumerate_pending_children_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async uint spawn (string program, Frida.SpawnOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public uint spawn_sync (string program, Frida.SpawnOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async void input (uint pid, GLib.Bytes data, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void input_sync (uint pid, GLib.Bytes data, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async void resume (uint pid, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void resume_sync (uint pid, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async void kill (uint pid, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void kill_sync (uint pid, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.Session attach (uint pid, Frida.SessionOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.Session attach_sync (uint pid, Frida.SessionOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async uint inject_library_file (uint pid, string path, string entrypoint, string data, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public uint inject_library_file_sync (uint pid, string path, string entrypoint, string data, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async uint inject_library_blob (uint pid, GLib.Bytes blob, string entrypoint, string data, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public uint inject_library_blob_sync (uint pid, GLib.Bytes blob, string entrypoint, string data, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async GLib.IOStream open_channel (string address, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public GLib.IOStream open_channel_sync (string address, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.Service open_service (string address, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.Service open_service_sync (string address, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async void unpair (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void unpair_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public delegate bool ProcessPredicate (Frida.Process process);

		public signal void child_added (Frida.Child child);
		public signal void child_removed (Frida.Child child);
		public signal void lost ();
		public signal void output (uint pid, int fd, GLib.Bytes data);
		public signal void process_crashed (Frida.Crash crash);
		public signal void spawn_added (Frida.Spawn spawn);
		public signal void spawn_removed (Frida.Spawn spawn);
		public signal void uninjected (uint id);
	}

	public sealed class RemoteDeviceOptions : GLib.Object {
		public GLib.TlsCertificate? certificate { get; set; }
		public string? origin { get; set; }
		public string? token { get; set; }
		public int keepalive_interval { get; set; }

		public RemoteDeviceOptions ();
	}

	public sealed class ApplicationList : GLib.Object {
		public int size ();
		public new Frida.Application @get (int index);
	}

	public sealed class Application : GLib.Object {
		public string identifier { get; construct; }
		public string name { get; construct; }
		public uint pid { get; construct; }
		public GLib.HashTable<string,GLib.Variant> parameters { get; construct; }
	}

	public sealed class ProcessList : GLib.Object {
		public int size ();
		public new Frida.Process @get (int index);
	}

	public sealed class Process : GLib.Object {
		public uint pid { get; construct; }
		public string name { get; construct; }
		public GLib.HashTable<string,GLib.Variant> parameters { get; construct; }
	}

	public sealed class ProcessMatchOptions : GLib.Object {
		public int timeout { get; set; }
		public Frida.Scope scope { get; set; }

		public ProcessMatchOptions ();
	}

	public sealed class SpawnOptions : GLib.Object {
		public string[]? argv { get; set; }
		public string[]? envp { get; set; }
		public string[]? env { get; set; }
		public string? cwd { get; set; }
		public Frida.Stdio stdio { get; set; }
		public GLib.HashTable<string,GLib.Variant> aux { get; set; }

		public SpawnOptions ();
	}

	public sealed class FrontmostQueryOptions : GLib.Object {
		public Frida.Scope scope { get; set; }

		public FrontmostQueryOptions ();
	}

	public sealed class ApplicationQueryOptions : GLib.Object {
		public Frida.Scope scope { get; set; }

		public ApplicationQueryOptions ();

		public void select_identifier (string identifier);
		public bool has_selected_identifiers ();
		public void enumerate_selected_identifiers (GLib.Func<string> func);
	}

	public sealed class ProcessQueryOptions : GLib.Object {
		public Frida.Scope scope { get; set; }

		public ProcessQueryOptions ();

		public void select_pid (uint pid);
		public bool has_selected_pids ();
		public void enumerate_selected_pids (GLib.Func<uint> func);
	}

	public sealed class SessionOptions : GLib.Object {
		public Frida.Realm realm { get; set; }
		public uint persist_timeout { get; set; }
		public string? emulated_agent_path { get; set; }

		public SessionOptions ();
	}

	public sealed class SpawnList : GLib.Object {
		public int size ();
		public new Frida.Spawn @get (int index);
	}

	public sealed class Spawn : GLib.Object {
		public uint pid { get; construct; }
		public string? identifier { get; construct; }
	}

	public sealed class ChildList : GLib.Object {
		public int size ();
		public new Frida.Child @get (int index);
	}

	public sealed class Child : GLib.Object {
		public uint pid { get; construct; }
		public uint parent_pid { get; construct; }
		public Frida.ChildOrigin origin { get; construct; }
		public string? identifier { get; construct; }
		public string? path { get; construct; }
		public string[]? argv { get; construct; }
		public string[]? envp { get; construct; }
	}

	public sealed class Crash : GLib.Object {
		public uint pid { get; construct; }
		public string process_name { get; construct; }
		public string summary { get; construct; }
		public string report { get; construct; }
		public GLib.HashTable<string,GLib.Variant> parameters { get; construct; }
	}

	public sealed class Bus : GLib.Object {
		public bool is_detached ();
		public async void attach (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void attach_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void post (string json, GLib.Bytes? data = null);

		public signal void detached ();
		public signal void message (string json, GLib.Bytes? data);
	}

	public sealed class Service : GLib.Object {
		public bool is_closed ();
		public async void activate (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void activate_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async void cancel (GLib.Cancellable? cancellable = null) throws GLib.IOError;
		public void cancel_sync (GLib.Cancellable? cancellable = null) throws GLib.IOError;
		public async GLib.Variant request (GLib.Variant parameters, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public GLib.Variant request_sync (GLib.Variant parameters, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;

		public signal void close ();
		public signal void message (GLib.Variant message);
	}

	public sealed class Session : GLib.Object, Frida.AgentMessageSink {
		public uint pid { get; construct; }
		public uint persist_timeout { get; construct; }

		public bool is_detached ();
		public async void detach (GLib.Cancellable? cancellable = null) throws GLib.IOError;
		public void detach_sync (GLib.Cancellable? cancellable = null) throws GLib.IOError;
		public async void resume (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void resume_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async void enable_child_gating (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void enable_child_gating_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async void disable_child_gating (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void disable_child_gating_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.Script create_script (string source, Frida.ScriptOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.Script create_script_sync (string source, Frida.ScriptOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.Script create_script_from_bytes (GLib.Bytes bytes, Frida.ScriptOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.Script create_script_from_bytes_sync (GLib.Bytes bytes, Frida.ScriptOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async GLib.Bytes compile_script (string source, Frida.ScriptOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public GLib.Bytes compile_script_sync (string source, Frida.ScriptOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async GLib.Bytes snapshot_script (string embed_script, Frida.SnapshotOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public GLib.Bytes snapshot_script_sync (string embed_script, Frida.SnapshotOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async void setup_peer_connection (Frida.PeerOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void setup_peer_connection_sync (Frida.PeerOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.PortalMembership join_portal (string address, Frida.PortalOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.PortalMembership join_portal_sync (string address, Frida.PortalOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;

		public signal void detached (Frida.SessionDetachReason reason, Frida.Crash? crash);
	}

	public sealed class Script : GLib.Object {
		public bool is_destroyed ();
		public async void load (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void load_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async void unload (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void unload_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async void eternalize (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void eternalize_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void post (string json, GLib.Bytes? data = null);
		public async void enable_debugger (uint16 port = 0, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void enable_debugger_sync (uint16 port = 0, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async void disable_debugger (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void disable_debugger_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;

		public signal void destroyed ();
		public signal void message (string json, GLib.Bytes? data);
	}

	public sealed class SnapshotOptions : GLib.Object {
		public string? warmup_script { get; set; }
		public Frida.ScriptRuntime runtime { get; set; }

		public SnapshotOptions ();
	}

	public sealed class ScriptOptions : GLib.Object {
		public string? name { get; set; }
		public GLib.Bytes? snapshot { get; set; }
		public Frida.SnapshotTransport snapshot_transport { get; set; }
		public Frida.ScriptRuntime runtime { get; set; }

		public ScriptOptions ();
	}

	public sealed class PeerOptions : GLib.Object {
		public string? stun_server { get; set; }

		public PeerOptions ();

		public void clear_relays ();
		public void add_relay (Frida.Relay relay);
		public void enumerate_relays (GLib.Func<Frida.Relay> func);
	}

	public sealed class Relay : GLib.Object {
		public string address { get; construct; }
		public string username { get; construct; }
		public string password { get; construct; }
		public Frida.RelayKind kind { get; construct; }

		public Relay (string address, string username, string password, Frida.RelayKind kind);
	}

	public sealed class PortalOptions : GLib.Object {
		public GLib.TlsCertificate? certificate { get; set; }
		public string? token { get; set; }
		public string[]? acl { get; set; }

		public PortalOptions ();
	}

	public sealed class PortalMembership : GLib.Object {
		public async void terminate (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void terminate_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
	}

	public sealed class RpcClient : GLib.Object {
		public weak Frida.RpcPeer peer { get; construct; }

		public RpcClient (Frida.RpcPeer peer);

		public async Json.Node call (string method, Json.Node[] args, GLib.Bytes? data, GLib.Cancellable? cancellable) throws Frida.Error, GLib.IOError;
		public bool try_handle_message (string json);
	}

	public interface RpcPeer : GLib.Object {
		public abstract async void post_rpc_message (string json, GLib.Bytes? data, GLib.Cancellable? cancellable) throws Frida.Error, GLib.IOError;
	}

	public interface Injector : GLib.Object {
		public static Frida.Injector @new ();

		public abstract async void close (GLib.Cancellable? cancellable = null) throws GLib.IOError;
		public void close_sync (GLib.Cancellable? cancellable = null) throws GLib.IOError;
		public abstract async uint inject_library_file (uint pid, string path, string entrypoint, string data, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public uint inject_library_file_sync (uint pid, string path, string entrypoint, string data, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public abstract async uint inject_library_blob (uint pid, GLib.Bytes blob, string entrypoint, string data, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public uint inject_library_blob_sync (uint pid, GLib.Bytes blob, string entrypoint, string data, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public abstract async void demonitor (uint id, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void demonitor_sync (uint id, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public abstract async uint demonitor_and_clone_state (uint id, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public uint demonitor_and_clone_state_sync (uint id, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public abstract async void recreate_thread (uint pid, uint id, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void recreate_thread_sync (uint pid, uint id, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public static Frida.Injector new_inprocess ();

		public signal void uninjected (uint id);
	}

	public sealed class PackageManager : GLib.Object {
		public string registry { get; set; }

		public PackageManager ();

		public async Frida.PackageSearchResult search (string query, Frida.PackageSearchOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.PackageSearchResult search_sync (string query, Frida.PackageSearchOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async Frida.PackageInstallResult install (Frida.PackageInstallOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public Frida.PackageInstallResult install_sync (Frida.PackageInstallOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;

		public signal void install_progress (Frida.PackageInstallPhase phase, double fraction, string? details = null);
	}

	public sealed class Package : GLib.Object {
		public string name { get; construct; }
		public string version { get; construct; }
		public string? description { get; construct; }
		public string? url { get; construct; }
	}

	public sealed class PackageList : GLib.Object {
		public int size ();
		public new Frida.Package @get (int index);
	}

	public class PackageSearchOptions : GLib.Object {
		public uint offset { get; set; }
		public uint limit { get; set; }

		public PackageSearchOptions ();
	}

	public sealed class PackageSearchResult : GLib.Object {
		public Frida.PackageList packages { get; construct; }
		public uint total { get; construct; }
	}

	public class PackageInstallOptions : GLib.Object {
		public string? project_root { get; set; }
		public Frida.PackageRole role { get; set; }

		public PackageInstallOptions ();

		public void clear_specs ();
		public void add_spec (string spec);
		public void clear_omits ();
		public void add_omit (Frida.PackageRole role);
	}

	public sealed class PackageInstallResult : GLib.Object {
		public Frida.PackageList packages { get; construct; }
	}

	public sealed class ControlService : GLib.Object {
		public Frida.EndpointParameters endpoint_params { get; construct; }
		public Frida.ControlServiceOptions options { get; construct; }

		public ControlService (Frida.EndpointParameters endpoint_params, Frida.ControlServiceOptions? options = null) throws Frida.Error;

		public async void start (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void start_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async void stop (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void stop_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async ControlService.with_device (Frida.Device device, Frida.EndpointParameters endpoint_params, Frida.ControlServiceOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
	}

	public sealed class ControlServiceOptions : GLib.Object {
		public string? sysroot { get; set; }
		public bool enable_preload { get; set; }
		public bool report_crashes { get; set; }

		public ControlServiceOptions ();
	}

	public sealed class PortalService : GLib.Object {
		public Frida.Device device { get; }
		public Frida.EndpointParameters cluster_params { get; construct; }
		public Frida.EndpointParameters? control_params { get; construct; }

		public PortalService (Frida.EndpointParameters cluster_params, Frida.EndpointParameters? control_params = null);

		public async void start (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void start_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async void stop (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void stop_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void kick (uint connection_id);
		public void post (uint connection_id, string json, GLib.Bytes? data = null);
		public void narrowcast (string tag, string json, GLib.Bytes? data = null);
		public void broadcast (string json, GLib.Bytes? data = null);
		public string[]? enumerate_tags (uint connection_id);
		public void tag (uint connection_id, string tag);
		public void untag (uint connection_id, string tag);

		public signal void authenticated (uint connection_id, string session_info);
		public signal void controller_connected (uint connection_id, GLib.SocketAddress remote_address);
		public signal void controller_disconnected (uint connection_id, GLib.SocketAddress remote_address);
		public signal void message (uint connection_id, string json, GLib.Bytes? data);
		public signal void node_connected (uint connection_id, GLib.SocketAddress remote_address);
		public signal void node_disconnected (uint connection_id, GLib.SocketAddress remote_address);
		public signal void node_joined (uint connection_id, Frida.Application application);
		public signal void node_left (uint connection_id, Frida.Application application);
		public signal void subscribe (uint connection_id);
	}

	public sealed class EndpointParameters : GLib.Object {
		public string? address { get; construct; }
		public uint16 port { get; construct; }
		public GLib.TlsCertificate? certificate { get; construct; }
		public string? origin { get; construct; }
		public Frida.AuthenticationService? auth_service { get; construct; }
		public GLib.File? asset_root { get; set; }

		public EndpointParameters (string? address = null, uint16 port = 0, GLib.TlsCertificate? certificate = null, string? origin = null, Frida.AuthenticationService? auth_service = null, GLib.File? asset_root = null);
	}

	public interface AuthenticationService : GLib.Object {
		public abstract async string authenticate (string token, GLib.Cancellable? cancellable) throws GLib.Error;
	}

	public sealed class StaticAuthenticationService : GLib.Object, Frida.AuthenticationService {
		public string token_hash { get; construct; }

		public StaticAuthenticationService (string token);
	}

	public sealed class FileMonitor : GLib.Object {
		public string path { get; construct; }

		public FileMonitor (string path);

		public async void enable (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void enable_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async void disable (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void disable_sync (GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;

		public signal void change (string file_path, string? other_file_path, GLib.FileMonitorEvent event);
	}

	public sealed class Compiler : GLib.Object {
		public Compiler (Frida.DeviceManager? manager = null);

		public async string build (string entrypoint, Frida.BuildOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public string build_sync (string entrypoint, Frida.BuildOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public async void watch (string entrypoint, Frida.WatchOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;
		public void watch_sync (string entrypoint, Frida.WatchOptions? options = null, GLib.Cancellable? cancellable = null) throws Frida.Error, GLib.IOError;

		public signal void diagnostics (GLib.Variant diagnostics);
		public signal void finished ();
		public signal void output (string bundle);
		public signal void starting ();
	}

	public class CompilerOptions : GLib.Object {
		public string? project_root { get; set; }
		public Frida.OutputFormat output_format { get; set; }
		public Frida.BundleFormat bundle_format { get; set; }
		public Frida.TypeCheckMode type_check { get; set; }
		public Frida.SourceMaps source_maps { get; set; }
		public Frida.JsCompression compression { get; set; }

		public CompilerOptions ();
	}

	public sealed class BuildOptions : Frida.CompilerOptions {
		public BuildOptions ();
	}

	public sealed class WatchOptions : Frida.CompilerOptions {
		public WatchOptions ();
	}


	public errordomain Error {
		SERVER_NOT_RUNNING,
		EXECUTABLE_NOT_FOUND,
		EXECUTABLE_NOT_SUPPORTED,
		PROCESS_NOT_FOUND,
		PROCESS_NOT_RESPONDING,
		INVALID_ARGUMENT,
		INVALID_OPERATION,
		PERMISSION_DENIED,
		ADDRESS_IN_USE,
		TIMED_OUT,
		NOT_SUPPORTED,
		PROTOCOL,
		TRANSPORT
	}

	public enum Runtime {
		GLIB,
		OTHER;
		public static Frida.Runtime from_nick (string nick) throws Frida.Error;
		public string to_nick ();
	}

	public enum DeviceType {
		LOCAL,
		REMOTE,
		USB;
		public static Frida.DeviceType from_nick (string nick) throws Frida.Error;
		public string to_nick ();
	}

	public enum PackageInstallPhase {
		INITIALIZING,
		PREPARING_DEPENDENCIES,
		RESOLVING_PACKAGE,
		FETCHING_RESOURCE,
		PACKAGE_ALREADY_INSTALLED,
		DOWNLOADING_PACKAGE,
		PACKAGE_INSTALLED,
		RESOLVING_AND_INSTALLING_ALL,
		COMPLETE
	}

	public enum PackageRole {
		RUNTIME,
		DEVELOPMENT,
		OPTIONAL,
		PEER
	}

	public enum OutputFormat {
		UNESCAPED,
		HEX_BYTES,
		C_STRING;
		public static Frida.OutputFormat from_nick (string nick) throws Frida.Error;
		public string to_nick ();
	}

	public enum BundleFormat {
		ESM,
		IIFE;
		public static Frida.BundleFormat from_nick (string nick) throws Frida.Error;
		public string to_nick ();
	}

	public enum TypeCheckMode {
		FULL,
		NONE;
		public static Frida.TypeCheckMode from_nick (string nick) throws Frida.Error;
		public string to_nick ();
	}

	public enum SourceMaps {
		INCLUDED,
		OMITTED;
		public static Frida.SourceMaps from_nick (string nick) throws Frida.Error;
		public string to_nick ();
	}

	public enum JsCompression {
		NONE,
		TERSER;
		public static Frida.JsCompression from_nick (string nick) throws Frida.Error;
		public string to_nick ();
	}

	public enum ChildOrigin {
		FORK,
		EXEC,
		SPAWN;
		public static Frida.ChildOrigin from_nick (string nick) throws Frida.Error;
		public string to_nick ();
	}

	public enum Realm {
		NATIVE,
		EMULATED;
		public static Frida.Realm from_nick (string nick) throws Frida.Error;
		public string to_nick ();
	}

	public enum RelayKind {
		TURN_UDP,
		TURN_TCP,
		TURN_TLS
	}

	public enum Scope {
		MINIMAL,
		METADATA,
		FULL;
		public static Frida.Scope from_nick (string nick) throws Frida.Error;
		public string to_nick ();
	}

	public enum ScriptRuntime {
		DEFAULT,
		QJS,
		V8;
		public static Frida.ScriptRuntime from_nick (string nick) throws Frida.Error;
		public string to_nick ();
	}

	public enum SessionDetachReason {
		APPLICATION_REQUESTED,
		PROCESS_REPLACED,
		PROCESS_TERMINATED,
		CONNECTION_TERMINATED,
		DEVICE_LOST;
		public static Frida.SessionDetachReason from_nick (string nick) throws Frida.Error;
		public string to_nick ();
	}

	public enum SnapshotTransport {
		INLINE,
		SHARED_MEMORY
	}

	public enum Stdio {
		INHERIT,
		PIPE;
		public static Frida.Stdio from_nick (string nick) throws Frida.Error;
		public string to_nick ();
	}
}
