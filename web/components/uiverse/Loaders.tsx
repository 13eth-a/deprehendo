// Loaders from Uiverse.io (MIT, see ./LICENSE). Markup is the original's; the
// styles are in styles/vendor.css, recolored to deprehendo's tokens.
//   ProgressBar: "yellow-panther-46" by gagan-gv (uiverse.io/gagan-gv/yellow-panther-46)
//   Spinner:     "massive-newt-28" by mrhyddenn (uiverse.io/mrhyddenn/massive-newt-28)

export function ProgressBar({ label }: { label: string }) {
  return (
    <div className="uv-progress" role="progressbar" aria-label={label} aria-busy="true">
      <div />
    </div>
  );
}

export function Spinner() {
  return <span className="uv-spinner" aria-hidden="true" />;
}
