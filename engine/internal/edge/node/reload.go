package node

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// commandReloader runs an arbitrary command to reload the terminator —
// `systemctl reload nginx` on a box where the unit owns the process and
// kapkan may not signal it directly.
type commandReloader []string

func (c commandReloader) Reload(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c[0], c[1:]...)
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(c, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
