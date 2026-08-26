import { pickem } from "pickem";

export async function selectRelease(apiUrl) {
  const response = await fetch(apiUrl);
  const releases = await response.json();
  const choices = releases.map((release) => ({
    label: release.title,
    description: release.summary,
    value: release.id,
  }));
  return pickem(choices, { searchable: false });
}
