package contracts

import capability "example.com/go-cross-package-safe-type-alias-interface-authorization/internal/capabilities"

type CapabilityAlias = capability.DeleteRepository

type SelectedRepository interface {
	CapabilityAlias
}

type SelectedAlias = SelectedRepository
