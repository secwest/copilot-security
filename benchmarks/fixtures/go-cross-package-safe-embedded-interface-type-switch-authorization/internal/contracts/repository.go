package contracts

import capability "example.com/go-cross-package-safe-embedded-interface-type-switch-authorization/internal/capabilities"

type SelectedRepository interface {
	capability.DeleteRepository
}
