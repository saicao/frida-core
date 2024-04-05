namespace Frida {
	public class ThreadIgnoreScope {
		public enum Kind {
			APPLICATION_THREAD,
			FRIDA_THREAD
		}

		private Kind kind;

		private Gum.Interceptor interceptor;

		private Gum.ThreadId thread_id;

		private uint num_ranges;
		private Gum.MemoryRange ranges[2];

		public ThreadIgnoreScope (Kind kind) {
			this.kind = kind;

			interceptor = Gum.Interceptor.obtain ();
			interceptor.ignore_current_thread ();

			if (kind == FRIDA_THREAD) {
				thread_id = Gum.Process.get_current_thread_id ();
				Gum.Cloak.add_thread (thread_id);

				num_ranges = Gum.Thread.try_get_ranges (ranges);
				for (var i = 0; i != num_ranges; i++)
					Gum.Cloak.add_range (ranges[i]);
			}
		}

		~ThreadIgnoreScope () {
			if (kind == FRIDA_THREAD) {
				for (var i = 0; i != num_ranges; i++)
					Gum.Cloak.remove_range (ranges[i]);

				Gum.Cloak.remove_thread (thread_id);
			}

			interceptor.unignore_current_thread ();
		}
	}

#if ANDROID
	public class ThreadCountCloaker : Object {
		private ReadFunc * read_slot;
		private static ReadFunc old_read_impl;

		private static string expected_magic = "%u (".printf (Posix.getpid ());

		[CCode (has_target = false)]
		private delegate ssize_t ReadFunc (int fd, void * buf, size_t count);

		construct {
			Gum.Module.enumerate_imports ("libart.so", imp => {
				if (imp.name == "read") {
					read_slot = (ReadFunc *) imp.slot;
					return false;
				}
				return true;
			});
			if (read_slot != null)
				old_read_impl = update_read_slot (on_read);
		}

		~ThreadCountCloaker () {
			if (read_slot != null)
				update_read_slot (old_read_impl);
		}

		private ReadFunc update_read_slot (ReadFunc new_impl) {
			Gum.PageProtection old_prot = READ;
			Gum.Memory.query_protection (read_slot, out old_prot);

			bool is_writable = (old_prot & Gum.PageProtection.WRITE) != 0;
			if (!is_writable)
				Gum.mprotect (read_slot, sizeof (void *), old_prot | WRITE);

			ReadFunc old_impl = *read_slot;
			*read_slot = new_impl;

			if (!is_writable)
				Gum.mprotect (read_slot, sizeof (void *), old_prot);

			return old_impl;
		}

		private static ssize_t on_read (int fd, void * buf, size_t count) {
			var n = old_read_impl (fd, buf, count);
			if (n <= 0)
				return n;

			if (!file_content_might_be_from_proc_self_stat (buf, n))
				return n;

			try {
				if (!file_descriptor_is_proc_self_stat (fd))
					return n;

				unowned string raw_str = (string) buf;
				string str = raw_str.substring (0, n);

				MatchInfo info;
				if (!/^(\d+ \(.+\)(?: [^ ]+){17}) \d+ (.+)/s.match (str, 0, out info))
					return n;
				string fields_before = info.fetch (1);
				string fields_after = info.fetch (2);

				// We cannot simply use the value we got from the kernel and subtract the number of cloaked threads,
				// as there's a chance the total may have changed in the last moment.
				uint num_uncloaked_threads = query_num_uncloaked_threads ();

				string adjusted_str = "%s %u %s".printf (fields_before, num_uncloaked_threads, fields_after);

				var adjusted_length = adjusted_str.length;
				if (adjusted_length > count)
					return n;
				Memory.copy (buf, adjusted_str, adjusted_length);
				n = adjusted_length;
			} catch (FileError e) {
			}

			return n;
		}

		private static bool file_content_might_be_from_proc_self_stat (void * content, ssize_t size) {
			if (size < expected_magic.length)
				return false;
			if (Memory.cmp (content, expected_magic, expected_magic.length) != 0)
				return false;
			unowned string raw_str = (string) content;
			return raw_str[size - 1] == '\n';
		}

		private static bool file_descriptor_is_proc_self_stat (int fd) throws FileError {
			string path = FileUtils.read_link ("/proc/self/fd/%d".printf (fd));
			uint pid = Posix.getpid ();
			return (path == "/proc/%u/stat".printf (pid)) ||
				(path == "/proc/%u/task/%u/stat".printf (pid, pid));
		}

		private static uint query_num_uncloaked_threads () throws FileError {
			uint n = 0;
			var dir = Dir.open ("/proc/self/task");
			string? name;
			while ((name = dir.read_name ()) != null) {
				var tid = uint.parse (name);
				if (!Gum.Cloak.has_thread (tid))
					n++;
			}
			return n;
		}
	}
#else
	public class ThreadCountCloaker : Object {
	}
#endif

#if LINUX
	public class ThreadListCloaker : Object, DirListFilter {
		private string our_dir_by_pid;
		private DirListCloaker cloaker;

		construct {
			our_dir_by_pid = "/proc/%u/task".printf (Posix.getpid ());
			cloaker = new DirListCloaker (this);
		}

		private bool matches_directory (string path) {
			return path == "/proc/self/task" || path == our_dir_by_pid;
		}

		private bool matches_file (string name) {
			var tid = (Gum.ThreadId) uint64.parse (name);
			return Gum.Cloak.has_thread (tid);
		}
	}

	public class FDListCloaker : Object, DirListFilter {
		private string our_dir_by_pid;
		private DirListCloaker cloaker;

		construct {
			our_dir_by_pid = "/proc/%u/fd".printf (Posix.getpid ());
			cloaker = new DirListCloaker (this);
		}

		private bool matches_directory (string path) {
			return path == "/proc/self/fd" || path == our_dir_by_pid;
		}

		private bool matches_file (string name) {
			var fd = int.parse (name);
			return Gum.Cloak.has_file_descriptor (fd);
		}
	}

	private class DirListCloaker : Object {
		public weak DirListFilter filter {
			get;
			construct;
		}

		private Gee.HashSet<Gum.InvocationListener> listeners = new Gee.HashSet<Gum.InvocationListener> ();
		private Gee.HashSet<unowned Posix.Dir> tracked_handles = new Gee.HashSet<unowned Posix.Dir> ();

		public DirListCloaker (DirListFilter filter) {
			Object (filter: filter);
		}

		construct {
			var interceptor = Gum.Interceptor.obtain ();

			unowned string libc = Gum.Process.query_libc_name ();

			var open_listener = new OpenDirListener (this);
			listeners.add (open_listener);
			interceptor.attach ((void *) Gum.Module.find_export_by_name (libc, "opendir"), open_listener);

			var close_listener = new CloseDirListener (this);
			listeners.add (close_listener);
			interceptor.attach ((void *) Gum.Module.find_export_by_name (libc, "closedir"), close_listener);

			var readdir_impl = Gum.Module.find_export_by_name (libc, "readdir");
			var readdir_listener = new ReadDirListener (this, LEGACY);
			listeners.add (readdir_listener);
			interceptor.attach ((void *) readdir_impl, readdir_listener);

			var readdir64_impl = Gum.Module.find_export_by_name (libc, "readdir64");
			if (readdir64_impl != 0 && readdir64_impl != readdir_impl) {
				var listener = new ReadDirListener (this, MODERN);
				listeners.add (listener);
				interceptor.attach ((void *) readdir64_impl, listener);
			}

			var readdir_r_impl = Gum.Module.find_export_by_name (libc, "readdir_r");
			var readdir_r_listener = new ReadDirRListener (this, LEGACY);
			listeners.add (readdir_r_listener);
			interceptor.attach ((void *) readdir_r_impl, readdir_r_listener);

			var readdir64_r_impl = Gum.Module.find_export_by_name (libc, "readdir64_r");
			if (readdir64_r_impl != 0 && readdir64_r_impl != readdir_r_impl) {
				var listener = new ReadDirRListener (this, MODERN);
				listeners.add (listener);
				interceptor.attach ((void *) readdir64_r_impl, listener);
			}
		}

		~DirListCloaker () {
			var interceptor = Gum.Interceptor.obtain ();

			foreach (var listener in listeners)
				interceptor.detach (listener);
		}

		public void start_tracking (Posix.Dir handle) {
			lock (tracked_handles)
				tracked_handles.add (handle);
		}

		public void stop_tracking (Posix.Dir handle) {
			lock (tracked_handles)
				tracked_handles.remove (handle);
		}

		public bool is_tracking (Posix.Dir handle) {
			lock (tracked_handles)
				return tracked_handles.contains (handle);
		}

		private class OpenDirListener : Object, Gum.InvocationListener {
			public weak DirListCloaker parent {
				get;
				construct;
			}

			public OpenDirListener (DirListCloaker parent) {
				Object (parent: parent);
			}

			public void on_enter (Gum.InvocationContext context) {
				Invocation * invocation = context.get_listener_invocation_data (sizeof (Invocation));

				invocation.path = (string *) context.get_nth_argument (0);
			}

			public void on_leave (Gum.InvocationContext context) {
				Invocation * invocation = context.get_listener_invocation_data (sizeof (Invocation));
				if (!parent.filter.matches_directory (invocation.path))
					return;

				unowned Posix.Dir? handle = (Posix.Dir?) context.get_return_value ();
				if (handle != null)
					parent.start_tracking (handle);
			}

			private struct Invocation {
				public string * path;
			}
		}

		private class CloseDirListener : Object, Gum.InvocationListener {
			public weak DirListCloaker parent {
				get;
				construct;
			}

			public CloseDirListener (DirListCloaker parent) {
				Object (parent: parent);
			}

			public void on_enter (Gum.InvocationContext context) {
				unowned Posix.Dir? handle = (Posix.Dir?) context.get_nth_argument (0);
				if (handle != null)
					parent.stop_tracking (handle);
			}
		}

		private class ReadDirListener : Object, Gum.InvocationListener {
			public weak DirListCloaker parent {
				get;
				construct;
			}

			public DirEntKind kind {
				get;
				construct;
			}

			public ReadDirListener (DirListCloaker parent, DirEntKind kind) {
				Object (parent: parent, kind: kind);
			}

			public void on_enter (Gum.InvocationContext context) {
				Invocation * invocation = context.get_listener_invocation_data (sizeof (Invocation));
				invocation.handle = (Posix.Dir?) context.get_nth_argument (0);
			}

			public void on_leave (Gum.InvocationContext context) {
				Invocation * invocation = context.get_listener_invocation_data (sizeof (Invocation));
				if (!parent.is_tracking (invocation.handle))
					return;

				var entry = context.get_return_value ();
				do {
					if (entry == null)
						return;

					var name = parse_dirent_name (entry, kind);

					if (name == "." || name == "..")
						return;

					if (!parent.filter.matches_file (name))
						return;

					var impl = (ReadDirFunc) context.function;
					entry = impl (invocation.handle);

					context.replace_return_value (entry);
				} while (true);
			}

			private struct Invocation {
				public unowned Posix.Dir? handle;
			}

			[CCode (has_target = false)]
			private delegate void * ReadDirFunc (Posix.Dir dir);
		}

		private class ReadDirRListener : Object, Gum.InvocationListener {
			public weak DirListCloaker parent {
				get;
				construct;
			}

			public DirEntKind kind {
				get;
				construct;
			}

			public ReadDirRListener (DirListCloaker parent, DirEntKind kind) {
				Object (parent: parent, kind: kind);
			}

			public void on_enter (Gum.InvocationContext context) {
				Invocation * invocation = context.get_listener_invocation_data (sizeof (Invocation));
				invocation.handle = (Posix.Dir?) context.get_nth_argument (0);
				invocation.entry = context.get_nth_argument (1);
				invocation.result = context.get_nth_argument (2);
			}

			public void on_leave (Gum.InvocationContext context) {
				Invocation * invocation = context.get_listener_invocation_data (sizeof (Invocation));
				if (!parent.is_tracking (invocation.handle))
					return;

				var result = (int) context.get_return_value ();
				do {
					if (result != 0)
						return;

					if (*invocation.result == null)
						return;

					var name = parse_dirent_name (*invocation.result, kind);

					if (name == "." || name == "..")
						return;

					if (!parent.filter.matches_file (name))
						return;

					var impl = (ReadDirRFunc) context.function;
					result = impl (invocation.handle, invocation.entry, invocation.result);

					context.replace_return_value ((void *) result);
				} while (true);
			}

			private struct Invocation {
				public unowned Posix.Dir? handle;
				public void * entry;
				public void ** result;
			}

			[CCode (has_target = false)]
			private delegate int ReadDirRFunc (Posix.Dir dir, void * entry, void ** result);
		}

		private static unowned string parse_dirent_name (void * entry, DirEntKind kind) {
			unowned string? name = null;

			if (kind == LEGACY) {
				unowned Posix.DirEnt ent = (Posix.DirEnt) entry;
				name = (string) ent.d_name;
			} else if (kind == MODERN) {
				unowned DirEnt64 ent = (DirEnt64) entry;
				name = (string) ent.d_name;
			}

			return name;
		}

		private enum DirEntKind {
			LEGACY,
			MODERN
		}
	}

	[Compact]
	public class DirEnt64 {
		public uint64 d_ino;
		public int64 d_off;
		public uint16 d_reclen;
		public uint8 d_type;
		public char d_name[256];
	}

	public interface DirListFilter : Object {
		public abstract bool matches_directory (string path);
		public abstract bool matches_file (string name);
	}
#else
	public class ThreadListCloaker : Object {
	}

	public class FDListCloaker : Object {
	}
#endif
}
