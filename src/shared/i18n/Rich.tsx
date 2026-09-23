import { Fragment } from "react";

// Half the sentences a person reads here lean on a bold word or a bit of code:
// "Binds *127.0.0.1* only", "Send it as `Authorization`". Moving those into
// locales/ as plain strings would flatten the emphasis, and splitting each
// sentence into three keys would leave a translator holding fragments with no
// sentence to put them in — and no way to move the bold word, which in another
// language rarely lands in the same place.
//
// So a locale value carries its own emphasis: *bold*, `code`, and \n for a line
// break. The translator moves the markers with the words. Anything richer than
// this — a link, an element with behaviour — stays in the JSX, with the text
// around it split into keys at the seam.
const TOKEN = /(\*[^*]+\*|`[^`]+`|\n)/g;

/** Renders one translated string, with *bold*, `code` and line breaks. */
export function Rich({ text }: { text: string }) {
  return (
    <>
      {text.split(TOKEN).map((part, i) => {
        if (part === "\n") return <br key={i} />;
        if (part.length > 2 && part.startsWith("*") && part.endsWith("*")) {
          return <strong key={i}>{part.slice(1, -1)}</strong>;
        }
        if (part.length > 2 && part.startsWith("`") && part.endsWith("`")) {
          return <code key={i}>{part.slice(1, -1)}</code>;
        }
        return <Fragment key={i}>{part}</Fragment>;
      })}
    </>
  );
}
