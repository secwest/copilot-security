package contracts

import capability "example.com/go-cross-package-type-alias-interface-delete-idor/internal/capabilities"

type CapabilityAlias = capability.DeleteRepository

type SelectedRepository interface {
	CapabilityAlias
}

type SelectedAlias = SelectedRepository
