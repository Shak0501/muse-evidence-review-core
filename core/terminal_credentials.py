"""Bounded, non-echoing terminal input. No browser, environment, file or echo fallback."""
import os
import select
import termios
import time
from .contracts import Refusal, require

class TerminalCredentials:
    def __init__(self,timeout=60,fd_factory=None):
        require(type(timeout) in (int,float) and 0.05<=timeout<=120,'CREDENTIAL_TIMEOUT_RANGE')
        self.timeout=timeout;self.fd_factory=fd_factory
    @property
    def default_terminal(self):return self.fd_factory is None
    def acquire(self,cancelled,still_allowed):
        fd=None;original=None;secret=bytearray();success=False;restored=False
        try:
            still_allowed();require(not cancelled.is_set(),'CREDENTIAL_CANCELLED')
            fd=self.fd_factory() if self.fd_factory else os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY)
            require(os.isatty(fd),'SECURE_TTY_REQUIRED')
            original=termios.tcgetattr(fd);hidden=list(original);hidden[6]=list(original[6])
            hidden[3]&=~(termios.ECHO|termios.ECHONL|termios.ICANON|termios.ISIG)
            hidden[6][termios.VMIN]=0;hidden[6][termios.VTIME]=0
            termios.tcsetattr(fd,termios.TCSAFLUSH,hidden)
            os.write(fd,b'\r\nMeta credential (hidden; Ctrl-C / Esc cancels; bounded timeout): ')
            deadline=time.monotonic()+self.timeout
            while True:
                require(not cancelled.is_set(),'CREDENTIAL_CANCELLED');still_allowed()
                left=deadline-time.monotonic();require(left>0,'CREDENTIAL_TIMEOUT')
                ready,_,_=select.select([fd],[],[],min(left,0.1))
                if not ready:continue
                try:ch=os.read(fd,1)
                except OSError:raise Refusal('CREDENTIAL_EOF') from None
                require(bool(ch),'CREDENTIAL_EOF')
                if ch in (b'\x03',b'\x1b'):raise Refusal('CREDENTIAL_CANCELLED')
                if ch==b'\x04':raise Refusal('CREDENTIAL_EOF')
                if ch in (b'\r',b'\n'):break
                if ch in (b'\x7f',b'\x08'):
                    if secret:secret[-1]=0;del secret[-1]
                    continue
                require(33<=ch[0]<=126 and len(secret)<4096,'CREDENTIAL_FORMAT')
                secret.extend(ch)
            require(16<=len(secret)<=4096,'CREDENTIAL_FORMAT')
            still_allowed();require(not cancelled.is_set(),'CREDENTIAL_CANCELLED')
            success=True
        except (KeyboardInterrupt,InterruptedError):raise Refusal('CREDENTIAL_CANCELLED') from None
        except Refusal:raise
        except (OSError,termios.error):raise Refusal('SECURE_TTY_REQUIRED') from None
        finally:
            if fd is not None:
                try:
                    # Discard unread pasted input as well as restoring modes. On
                    # macOS this also prevents pending-input retyping on ICANON.
                    if original is not None:termios.tcsetattr(fd,termios.TCSAFLUSH,original)
                    restored=True
                    os.write(fd,b'\r\n')
                except (OSError,termios.error):restored=False
                finally:os.close(fd)
            if not success or not restored:secret[:]=b'\x00'*len(secret)
            if success and not restored:raise Refusal('TERMINAL_RESTORE_FAILED') from None
        return secret
