#!/usr/bin/env python3
"""Small fd-relative filesystem primitive for the macop installer.

The installer deliberately keeps the authority for every mutable directory as
its device/inode pair.  A pathname is only used to open that directory; every
operation verifies the pair after opening with O_NOFOLLOW and then acts on a
single, slash-free leaf through that descriptor.  Consequently a rename or a
symlink substitution between installer phases fails closed instead of moving
files in the replacement tree.
"""

from __future__ import annotations

import errno
import os
import secrets
import stat
import sys


def die(message: str) -> "None":
    raise SystemExit(f"install-fs: {message}")


def leaf(value: str) -> str:
    if not value or value in {".", ".."} or "/" in value:
        die("leaf names must be non-empty and slash-free")
    return value


def identity(st: os.stat_result) -> str:
    return f"{st.st_dev}:{st.st_ino}"


def open_dir(path: str, expected: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        die(f"cannot open validated directory {path}: {exc.strerror}")
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode) or identity(st) != expected:
            die(f"directory identity changed: {path}")
        return fd
    except BaseException:
        os.close(fd)
        raise


def lstat_at(dfd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def ensure_safe_existing(dfd: int, name: str, kind: str | None = None) -> os.stat_result:
    st = lstat_at(dfd, name)
    if st is None:
        die(f"required leaf is missing: {name}")
    if stat.S_ISLNK(st.st_mode):
        die(f"refusing symlink leaf: {name}")
    if kind == "file" and not stat.S_ISREG(st.st_mode):
        die(f"leaf is not a regular file: {name}")
    if kind == "dir" and not stat.S_ISDIR(st.st_mode):
        die(f"leaf is not a directory: {name}")
    return st


def open_child_dir(dfd: int, name: str, expected: str) -> int:
    """Open a validated directory leaf without re-resolving its parent path."""
    before = ensure_safe_existing(dfd, name, "dir")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        child = os.open(name, flags, dir_fd=dfd)
    except OSError as exc:
        die(f"cannot open validated child directory {name}: {exc.strerror}")
    try:
        after = os.fstat(child)
        if (
            identity(before) != identity(after)
            or identity(after) != expected
            or not stat.S_ISDIR(after.st_mode)
        ):
            die(f"child directory identity changed: {name}")
        return child
    except BaseException:
        os.close(child)
        raise


def write_record(dfd: int, name: str, value: str) -> None:
    temporary = ".record-" + secrets.token_hex(10)
    child = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
        dir_fd=dfd,
    )
    complete = False
    try:
        payload = memoryview(value.encode())
        while payload:
            written = os.write(child, payload)
            if written <= 0:
                die("record write made no progress")
            payload = payload[written:]
        os.fsync(child)
        complete = True
    finally:
        os.close(child)
        if not complete:
            try:
                os.unlink(temporary, dir_fd=dfd)
            except FileNotFoundError:
                pass
    old = lstat_at(dfd, name)
    if old is not None and (stat.S_ISLNK(old.st_mode) or not stat.S_ISREG(old.st_mode)):
        os.unlink(temporary, dir_fd=dfd)
        die(f"unsafe record destination: {name}")
    os.rename(temporary, name, src_dir_fd=dfd, dst_dir_fd=dfd)
    os.fsync(dfd)


def assert_child_identity(dfd: int, name: str, expected: str) -> None:
    """Require that a visible directory leaf is still the retained child."""
    current = ensure_safe_existing(dfd, name, "dir")
    if identity(current) != expected:
        die(f"child directory identity changed: {name}")


def remove_tree_at(dfd: int, name: str) -> None:
    child = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=dfd)
    opened = os.fstat(child)
    retired = ""
    try:
        for _ in range(100):
            retired = ".remove-" + secrets.token_hex(10)
            if lstat_at(dfd, retired) is not None:
                continue
            assert_child_identity(dfd, name, identity(opened))
            os.rename(name, retired, src_dir_fd=dfd, dst_dir_fd=dfd)
            moved = ensure_safe_existing(dfd, retired, "dir")
            if identity(moved) != identity(opened):
                die(f"retired directory identity changed: {name}")
            os.fsync(dfd)
            break
        else:
            die("could not allocate unique removal leaf")
        for child_name in os.listdir(child):
            st = os.stat(child_name, dir_fd=child, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode):
                remove_tree_at(child, child_name)
            else:
                # A symlink is never followed; deleting it is safe.
                os.unlink(child_name, dir_fd=child)
        os.fsync(child)
    finally:
        os.close(child)
    # Darwin has no fd-relative equivalent of unlinkat(AT_EMPTY_PATH) for an
    # opened directory. A final rmdir(retired) would therefore re-resolve a
    # mutable name and could report success after deleting a same-UID
    # replacement rather than the inode traversed above. Keep the emptied,
    # randomly named tombstone: the public leaf was already removed atomically,
    # and no pathname-only delete is allowed to weaken that identity binding.
    os.fsync(dfd)


def fsync_tree_at(dfd: int, name: str) -> None:
    before = lstat_at(dfd, name)
    if before is None:
        die(f"required staged leaf is missing: {name}")
    if stat.S_ISLNK(before.st_mode):
        return
    if stat.S_ISREG(before.st_mode):
        child = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=dfd)
        try:
            after = os.fstat(child)
            if identity(before) != identity(after) or not stat.S_ISREG(after.st_mode):
                die(f"file identity changed while syncing: {name}")
            os.fsync(child)
        finally:
            os.close(child)
        return
    if stat.S_ISDIR(before.st_mode) and not stat.S_ISLNK(before.st_mode):
        child = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=dfd,
        )
        try:
            after = os.fstat(child)
            if identity(before) != identity(after) or not stat.S_ISDIR(after.st_mode):
                die(f"directory identity changed while syncing: {name}")
            for child_name in os.listdir(child):
                fsync_tree_at(child, child_name)
            os.fsync(child)
        finally:
            os.close(child)
        return
    die(f"unsupported staged filesystem object: {name}")


def main(argv: list[str]) -> None:
    if not argv:
        die("missing command")
    command, *args = argv
    if command == "id" and len(args) == 1:
        fd = os.open(args[0], os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            st = os.fstat(fd)
            if not stat.S_ISDIR(st.st_mode):
                die("not a directory")
            print(identity(st))
        finally:
            os.close(fd)
        return
    if command == "assert" and len(args) == 2:
        fd = open_dir(args[0], args[1]); os.close(fd); return
    if command == "mkdir" and len(args) == 4:
        path, expected, name, mode = args; name = leaf(name); fd = open_dir(path, expected)
        try:
            if lstat_at(fd, name) is not None: die(f"leaf already exists: {name}")
            os.mkdir(name, int(mode, 8), dir_fd=fd); os.fsync(fd)
        finally: os.close(fd)
        return
    if command == "mktemp" and len(args) == 4:
        path, expected, prefix, kind = args; leaf(prefix + "x")
        if kind not in {"file", "dir"}: die("mktemp kind must be file or dir")
        fd = open_dir(path, expected)
        try:
            for _ in range(100):
                name = prefix + secrets.token_hex(10)
                try:
                    if kind == "file":
                        child = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=fd)
                        os.close(child)
                    else: os.mkdir(name, 0o700, dir_fd=fd)
                    os.fsync(fd); print(name); return
                except FileExistsError: pass
            die("could not allocate unique temporary leaf")
        finally: os.close(fd)
    if command == "record" and len(args) == 4:
        path, expected, name, value = args; name = leaf(name); fd = open_dir(path, expected)
        try:
            write_record(fd, name, value)
        finally: os.close(fd)
        return
    if command == "read" and len(args) == 3:
        path, expected, name = args; name = leaf(name); fd = open_dir(path, expected)
        try:
            ensure_safe_existing(fd, name, "file")
            child = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            try: sys.stdout.write(os.read(child, 1024 * 1024).decode())
            finally: os.close(child)
        finally: os.close(fd)
        return
    if command == "exists" and len(args) == 4:
        path, expected, name, kind = args; name = leaf(name); fd = open_dir(path, expected)
        try:
            st = lstat_at(fd, name)
            if st is None: raise SystemExit(1)
            if stat.S_ISLNK(st.st_mode): die(f"unsafe symlink leaf: {name}")
            if kind == "file" and not stat.S_ISREG(st.st_mode): raise SystemExit(1)
            if kind == "dir" and not stat.S_ISDIR(st.st_mode): raise SystemExit(1)
        finally: os.close(fd)
        return
    if command == "absent" and len(args) == 3:
        path, expected, name = args; name = leaf(name); fd = open_dir(path, expected)
        try:
            if lstat_at(fd, name) is not None:
                die(f"leaf unexpectedly exists: {name}")
        finally: os.close(fd)
        return
    if command == "absent-prefix" and len(args) == 3:
        path, expected, prefix = args
        if not prefix or "/" in prefix:
            die("prefix must be non-empty and slash-free")
        fd = open_dir(path, expected)
        try:
            for name in os.listdir(fd):
                if name.startswith(prefix):
                    die(f"matching leaf unexpectedly exists: {name}")
        finally:
            os.close(fd)
        return
    if command == "child-id" and len(args) == 4:
        path, expected, name, kind = args; name = leaf(name)
        if kind != "dir":
            die("child-id currently supports only directory leaves")
        fd = open_dir(path, expected)
        try:
            before = ensure_safe_existing(fd, name, kind)
            child = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=fd,
            )
            try:
                after = os.fstat(child)
                if identity(before) != identity(after) or not stat.S_ISDIR(after.st_mode):
                    die(f"child directory identity changed: {name}")
                print(identity(after))
            finally:
                os.close(child)
        finally:
            os.close(fd)
        return
    if command == "record-child" and len(args) == 6:
        path, expected, child_name, child_expected, name, value = args; child_name = leaf(child_name); name = leaf(name)
        fd = open_dir(path, expected)
        try:
            child = open_child_dir(fd, child_name, child_expected)
            try:
                write_record(child, name, value)
            finally:
                os.close(child)
        finally:
            os.close(fd)
        return
    if command == "read-child" and len(args) == 5:
        path, expected, child_name, child_expected, name = args; child_name = leaf(child_name); name = leaf(name)
        fd = open_dir(path, expected)
        try:
            child = open_child_dir(fd, child_name, child_expected)
            try:
                ensure_safe_existing(child, name, "file")
                record = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=child)
                try:
                    sys.stdout.write(os.read(record, 1024 * 1024).decode())
                finally:
                    os.close(record)
            finally:
                os.close(child)
        finally:
            os.close(fd)
        return
    if command == "absent-child" and len(args) == 5:
        path, expected, child_name, child_expected, name = args; child_name = leaf(child_name); name = leaf(name)
        fd = open_dir(path, expected)
        try:
            child = open_child_dir(fd, child_name, child_expected)
            try:
                if lstat_at(child, name) is not None:
                    die(f"child leaf unexpectedly exists: {name}")
            finally:
                os.close(child)
        finally:
            os.close(fd)
        return
    if command == "remove-child" and len(args) == 6:
        path, expected, child_name, child_expected, name, kind = args; child_name = leaf(child_name); name = leaf(name)
        if kind not in {"file", "dir"}:
            die("remove-child kind must be file or dir")
        fd = open_dir(path, expected)
        try:
            child = open_child_dir(fd, child_name, child_expected)
            try:
                ensure_safe_existing(child, name, kind)
                if kind == "file":
                    os.unlink(name, dir_fd=child)
                else:
                    remove_tree_at(child, name)
                os.fsync(child)
            finally:
                os.close(child)
        finally:
            os.close(fd)
        return
    if command == "retire-child" and len(args) == 5:
        path, expected, child_name, child_expected, prefix = args; child_name = leaf(child_name)
        leaf(prefix + "x")
        fd = open_dir(path, expected)
        try:
            child = open_child_dir(fd, child_name, child_expected)
            try:
                for _ in range(100):
                    retired = prefix + secrets.token_hex(10)
                    if lstat_at(fd, retired) is not None:
                        continue
                    # The lock's PID remains inside the retained directory
                    # until this rename is complete. A concurrent acquirer
                    # therefore cannot mistake it for stale and replace the
                    # visible lock before the handoff is atomic.
                    assert_child_identity(fd, child_name, child_expected)
                    os.rename(child_name, retired, src_dir_fd=fd, dst_dir_fd=fd)
                    os.fsync(fd)
                    print(retired)
                    return
                die("could not allocate unique retired child leaf")
            finally:
                os.close(child)
        finally:
            os.close(fd)
    if command == "rmdir-child" and len(args) == 4:
        path, expected, child_name, child_expected = args; child_name = leaf(child_name)
        fd = open_dir(path, expected)
        try:
            child = open_child_dir(fd, child_name, child_expected)
            try:
                # This is deliberately non-recursive. If a replacement or an
                # unexpected leaf appears, preserve it and fail closed.
                assert_child_identity(fd, child_name, child_expected)
                os.rmdir(child_name, dir_fd=fd)
                os.fsync(fd)
            finally:
                os.close(child)
        finally:
            os.close(fd)
        return
    if command == "rename" and len(args) == 6:
        src_path, src_id, src_name, dst_path, dst_id, dst_name = args; src_name = leaf(src_name); dst_name = leaf(dst_name)
        sfd = open_dir(src_path, src_id); dfd = open_dir(dst_path, dst_id)
        try:
            ensure_safe_existing(sfd, src_name)
            if lstat_at(dfd, dst_name) is not None: die(f"rename destination already exists: {dst_name}")
            os.rename(src_name, dst_name, src_dir_fd=sfd, dst_dir_fd=dfd); os.fsync(sfd); os.fsync(dfd)
        finally: os.close(dfd); os.close(sfd)
        return
    if command == "sync" and len(args) == 4:
        path, expected, name, kind = args; name = leaf(name)
        if kind not in {"file", "dir"}:
            die("sync kind must be file or dir")
        fd = open_dir(path, expected)
        try:
            ensure_safe_existing(fd, name, kind)
            fsync_tree_at(fd, name)
            os.fsync(fd)
        finally:
            os.close(fd)
        return
    if command == "remove" and len(args) == 4:
        path, expected, name, kind = args; name = leaf(name); fd = open_dir(path, expected)
        try:
            st = ensure_safe_existing(fd, name, kind)
            if kind == "file": os.unlink(name, dir_fd=fd)
            elif kind == "dir": remove_tree_at(fd, name)
            else: die("remove kind must be file or dir")
            os.fsync(fd)
        finally: os.close(fd)
        return
    die("invalid command arguments")


if __name__ == "__main__":
    main(sys.argv[1:])
