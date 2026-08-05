package contracts

import capability "example.com/go-cross-package-embedded-interface-type-switch-delete-idor/internal/capabilities"

type SelectedRepository interface {
	capability.DeleteRepository
}
