const documents = new Map([
  ["public", "bounded-public-document"],
  ["secret", "bounded-secret-document"],
]);

async function loadDocument(slug) {
  return documents.get(slug) ?? "missing-document";
}

export async function getServerSideProps({ params }) {
  const document = await loadDocument(params.slug);
  return { props: { document } };
}

export default function Page({ document }) {
  return <main id="document">{document}</main>;
}
