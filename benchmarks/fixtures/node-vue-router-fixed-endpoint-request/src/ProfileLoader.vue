<script setup>
import { useRoute } from "vue-router";

const route = useRoute();
const resource = route.query.resource;
const profilePromise = fetch("/api/search?q=" + encodeURIComponent(resource));
</script>

<template><div data-profile-loader /></template>
