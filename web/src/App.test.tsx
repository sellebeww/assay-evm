import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { App } from "./App";
import { sample } from "./test/samples";

function upload(text: string, name = "report.json") {
  const input = document.querySelector<HTMLInputElement>('input[type="file"]');
  if (input === null) throw new Error("no file input");
  const file = new File([text], name, { type: "application/json" });
  fireEvent.change(input, { target: { files: [file] } });
}

describe("App", () => {
  it("shows the verdict, the failing oracle and the bounds of a rejected report", async () => {
    render(<App />);
    upload(sample("rejected"));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("REJECTED"));
    const variant = screen.getByRole("region", { name: "variant oracle" });
    expect(variant).toHaveTextContent("FAIL");
    expect(variant).toHaveTextContent("variant_found");
    expect(variant).toHaveTextContent("src/Vault.sol:7");
    expect(screen.getByText(/valid within these bounds only/)).toBeInTheDocument();
  });

  it("never calls a verified patch proven", async () => {
    render(<App />);
    upload(sample("verified"));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("VERIFIED_WITHIN_BOUNDS"));
    expect(screen.getByRole("status")).toHaveTextContent("not a proof");
  });

  it("shows text from a report as text and runs no markup", async () => {
    const document_ = JSON.parse(sample("rejected"));
    const payload = '<img src=x onerror="window.__pwned = true"><script>window.__pwned = true</script>';
    document_.oracles[2].reasons[0].detail = payload;
    render(<App />);
    upload(JSON.stringify(document_));
    await waitFor(() => expect(screen.getByRole("status")).toBeInTheDocument());
    expect(screen.getByRole("region", { name: "variant oracle" })).toHaveTextContent(payload);
    expect(document.querySelector("img")).toBeNull();
    expect(document.querySelector("script")).toBeNull();
    expect((window as unknown as { __pwned?: boolean }).__pwned).toBeUndefined();
  });

  it("explains a file that cannot be shown", async () => {
    render(<App />);
    upload("not json");
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("not valid JSON"));
  });

  it("marks the bundled examples as synthetic", async () => {
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const name = String(input).split("/").pop()?.replace(".json", "") ?? "";
      return new Response(sample(name));
    }) as typeof fetch;
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "inconclusive" }));
    await waitFor(() => expect(screen.getByText(/Synthetic example/)).toBeInTheDocument());
    expect(screen.getByRole("status")).toHaveTextContent("INCONCLUSIVE");
  });
});
