-- | Out-of-band ground-truth monitor.
--
-- The whole experiment rests on comparing two independent records:
--
--   * what the AGENT believes happened (the tool's self-report / the observation
--     it received)
--   * what ACTUALLY happened (this log, written by the substrate from the real
--     syscall stream, independent of anything the agent/harness can see)
--
-- Keeping this log out-of-band is what makes belief-vs-reality airtight: the
-- traced process tree never reads or writes it. Each record exposes the tamper
-- directly: for a redirect, requested /= actual; for a spoof, realRet /= returned.
module Substrate.Monitor
  ( GroundTruth(..)
  , logEvent
  , newRun
  ) where

import Data.Time.Clock.POSIX (getPOSIXTime)
import System.IO

-- | One ground-truth record of a real syscall-level event.
data GroundTruth = GroundTruth
  { gtPid       :: !Int
  , gtSyscall   :: !String   -- e.g. "openat"
  , gtRequested :: !String   -- the path/arg the tool's call asked for
  , gtActual    :: !String   -- what the substrate actually caused
  , gtRealRet   :: !String   -- the real return value ("" if n/a)
  , gtReturned  :: !String   -- the value handed back to the child ("" if n/a)
  , gtTampered  :: !String   -- "redirect" | "spoof" | "none"
  }

-- | Append one event as a JSON line to the ground-truth log.
logEvent :: FilePath -> GroundTruth -> IO ()
logEvent path gt = do
  t <- getPOSIXTime
  withFile path AppendMode $ \h ->
    hPutStrLn h $ concat
      [ "{\"ts\":",         show (realToFrac t :: Double)
      , ",\"pid\":",        show (gtPid gt)
      , ",\"syscall\":",    esc (gtSyscall gt)
      , ",\"requested\":",  esc (gtRequested gt)
      , ",\"actual\":",     esc (gtActual gt)
      , ",\"real_ret\":",   esc (gtRealRet gt)
      , ",\"returned\":",   esc (gtReturned gt)
      , ",\"tampered\":",   esc (gtTampered gt)
      , "}" ]
  where
    esc = show  -- show on String yields a quoted, JSON-compatible escaped literal

-- | Truncate/create the ground-truth log for a new run.
newRun :: FilePath -> IO ()
newRun path = writeFile path ""
