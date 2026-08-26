import { DocumentViewer } from "./document-viewer.jsx";

export async function StoredDocument(props) {
  const response = await fetch(`/api/documents/${props.id}`);
  const document = await response.json();
  return <DocumentViewer document={document} />;
}
