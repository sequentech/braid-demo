<script>
  import { invoke } from "@tauri-apps/api/tauri"
  import { DataTable } from "carbon-components-svelte";
  import { Grid, Row, Column } from "carbon-components-svelte";
  import { Content, Button, TextInput, Tile } from "carbon-components-svelte";
  
  let trustees = 2;
  let threshold = 2;
  let count = 100;

  let info = {};
  let message_rows = [];
  let trustee_rows = [];
  let last_messages_rows = [];
  let log = "Ready";
  let active = "";

  async function step() {
    log = "Working..";
    info = await invoke("step", { active })
    message_rows = info.messages;
    trustee_rows = info.trustee_rows;
    last_messages_rows = info.last_messages;
    log = info.log;
  }
  
  async function reset() {
    info = await invoke("reset", { trustees, threshold })
    message_rows = info.messages;
    trustee_rows = info.trustee_rows;
    last_messages_rows = info.last_messages;
    log = info.log;
  }

  async function ballots() {
    log = "Working..";
    info = await invoke("ballots", { count })
    message_rows = info.messages;
    trustee_rows = info.trustee_rows;
    last_messages_rows = info.last_messages;
    log = info.log;
  }

  reset();
  </script>

<Content>
<div class="top">
<Grid fullWidth>
  <Row>
    <Column>
      <DataTable size="compact" zebra stickyHeader
      headers={[
        { key: "type_", value: "Message" },
        { key: "sender", value: "Sender" },
        { key: "artifact", value: "Artifact" },
      ]}
      rows={message_rows}
    /></Column>
    <Column>
      <DataTable size="compact" zebra stickyHeader
      headers={[
        { key: "position", value: "Trustee"},
        { key: "statement_data", value: "Statements"},
        { key: "artifact_data", value: "Artifacts" },
      ]}
      rows={trustee_rows}
    />
    </Column>
  </Row>
  <Row padding>
    <Column>
      <DataTable size="compact" zebra stickyHeader
      headers={[
        { key: "type_", value: "Last Message" },
        { key: "sender", value: "Sender" },
        { key: "artifact", value: "Artifact" },
      ]}
      rows={last_messages_rows}
      />
    </Column>
  </Row>
  <Row>
    
  </Row>
</Grid>
</div>

<div class="footer">
  <Grid>
    <Row>  
      <Column>
        <TextInput type="number" labelText="Ballot count" placeholder="Enter # of ballots to generate" bind:value={count} />
        <TextInput labelText="Active trustee #" placeholder="Entre trustee to step" bind:value={active} />
        
      </Column>
      <Column>
        <TextInput type="number" labelText="Number of trustees" placeholder="Enter trustee #" bind:value={trustees} />
        <TextInput type="number" labelText="Threshold" placeholder="Enter threshold #" bind:value={threshold} />
      </Column>
    
    
    </Row>
    <Row padding>
    <Column>
      <Button on:click={() => step()}>Step</Button>
      <Button on:click={() => ballots()}>Post ballots</Button>
    </Column>
  <Column>
  
  <Button on:click={() => reset()}>Reset</Button>
  </Column>
  
  </Row>
  
  </Grid>
  <Tile>{log}</Tile>
  </div>
  </Content>


<style>
  .footer {
  position: fixed;
  left: 0;
  bottom: 0;
  width: 100%;
  color: white;
  text-align: left;
}
.top {
  width: 100%;
  text-align: left;
}
</style>
